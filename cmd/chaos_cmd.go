package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/chaos"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// init wires the chaos transport into pkg/provider so any cloop subcommand
// (run, ui, daemon, …) honours the on-disk fault file at .cloop/chaos/active.json.
//
// The middleware itself is fully transparent when chaos.Global() is nil, so
// installing it here imposes no runtime cost on builds where chaos is never
// invoked. The global controller is bound lazily by `cloop chaos inject` —
// long-running processes (cloop ui) pick up faults written by other CLI
// invocations without restart via the file-watcher in chaos.Controller.
func init() {
	provider.SetHTTPMiddleware(func(base http.RoundTripper) http.RoundTripper {
		return &chaos.Transport{Base: base}
	})

	chaosCmd.AddCommand(chaosInjectCmd)
	chaosCmd.AddCommand(chaosClearCmd)
	chaosCmd.AddCommand(chaosListCmd)
	chaosCmd.AddCommand(chaosReportCmd)
	chaosCmd.AddCommand(chaosSuiteCmd)

	chaosInjectCmd.Flags().Duration("duration", 30*time.Second, "How long the fault stays active")
	chaosInjectCmd.Flags().Float64("probability", 1.0, "Probability of injection per candidate event (0..1)")
	chaosInjectCmd.Flags().String("note", "", "Free-form note recorded with the run (e.g. ballast size or slow-disk delay like '150ms')")
	chaosInjectCmd.Flags().Bool("wait", true, "Block until the fault expires; with --wait=false the CLI returns immediately and the daemon clears the fault on its own")

	chaosReportCmd.Flags().Int("limit", 50, "Maximum number of recent runs to consider")
	chaosSuiteCmd.Flags().Bool("clear-after", true, "Clear any leftover faults when the suite finishes")

	rootCmd.AddCommand(chaosCmd)
}

var chaosCmd = &cobra.Command{
	Use:   "chaos",
	Short: "Inject simulated failures to test cloop's resilience",
	Long: `Inject simulated failures (provider timeouts, 429/500 responses, sqlite
busy contention, network flaps, disk-full, slow disk) to test how the system
handles them.

Faults are persisted to .cloop/chaos/active.json so they take effect inside
any cloop process (cloop ui, cloop run, …) without restart. Each injection is
recorded in the chaos_runs SQLite table along with the observed outcome so
'cloop chaos report' can summarise resilience over time.

Available fault types:
  provider-timeout      every outbound provider HTTP call hangs past deadline
  provider-429          provider responses replaced with HTTP 429 (rate limited)
  provider-500          provider responses replaced with HTTP 500
  sqlite-busy           sibling write transaction held on .cloop/state.db
  network-flap          fraction of HTTP requests fail with dial error
  disk-full-simulation  ballast file occupies disk space under .cloop/chaos
  slow-disk             configured artificial delay on atomicfile writes`,
}

var chaosInjectCmd = &cobra.Command{
	Use:   "inject <fault-type>",
	Short: "Activate a fault for the configured duration",
	Long: `Inject one fault and (by default) wait for its window to close,
recording the observed outcome in the chaos_runs table.

Examples:
  cloop chaos inject provider-429 --duration 1m
  cloop chaos inject sqlite-busy --duration 10s --note 'long backup'
  cloop chaos inject slow-disk --note 250ms --duration 30s
  cloop chaos inject network-flap --probability 0.5 --duration 2m`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ftype, err := chaos.ParseFaultType(args[0])
		if err != nil {
			return err
		}
		duration, _ := cmd.Flags().GetDuration("duration")
		probability, _ := cmd.Flags().GetFloat64("probability")
		note, _ := cmd.Flags().GetString("note")
		wait, _ := cmd.Flags().GetBool("wait")

		if duration <= 0 {
			return fmt.Errorf("--duration must be positive, got %s", duration)
		}
		if probability < 0 || probability > 1 {
			return fmt.Errorf("--probability must be in [0,1], got %v", probability)
		}

		workDir, _ := os.Getwd()
		controller := chaos.NewController(workDir)
		// Set as global so any HTTP client constructed by THIS process also
		// honours the fault — useful for `cloop chaos inject` followed by an
		// in-process probe from a script.
		prev := chaos.SetGlobal(controller)
		defer chaos.SetGlobal(prev)

		dbPath := filepath.Join(workDir, ".cloop", "state.db")
		store, storeErr := chaos.OpenStore(dbPath)
		if storeErr != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr,
				"warning: could not open chaos_runs store (%v) — proceeding without persistence\n",
				storeErr)
		}
		defer func() {
			if store != nil {
				_ = store.Close()
			}
		}()

		now := time.Now()
		fault := chaos.Fault{
			Type:        ftype,
			StartedAt:   now,
			Until:       now.Add(duration),
			Probability: probability,
			Note:        note,
		}

		runID := int64(0)
		if store != nil {
			id, err := store.Insert(chaos.Run{
				FaultType:   ftype,
				Probability: probability,
				StartedAt:   now,
				Outcome:     chaos.OutcomeUnknown,
				Note:        note,
			})
			if err == nil {
				runID = id
				fault.ID = id
			}
		}

		if err := controller.Inject(fault); err != nil {
			finaliseRun(store, runID, time.Since(now), chaos.OutcomeCrashed,
				fmt.Sprintf("inject failed: %v", err), note)
			return err
		}

		header := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)
		header.Printf("cloop chaos — injected %s\n", ftype)
		dim.Printf("  duration:    %s\n", duration)
		dim.Printf("  probability: %.2f\n", probability)
		if note != "" {
			dim.Printf("  note:        %s\n", note)
		}
		dim.Printf("  expires:     %s\n", fault.Until.Format(time.RFC3339))

		// For sqlite-busy we hold the write lock from this process so the
		// fault has a real effect even when no other cloop process is doing
		// chaos-aware work. The HTTP-side faults are honoured by any process
		// that has the chaos middleware installed.
		var holder *chaos.BusyHolder
		if ftype == chaos.FaultSQLiteBusy {
			holder = chaos.NewBusyHolder(dbPath)
			if err := holder.Start(cmd.Context()); err != nil {
				_ = controller.Clear()
				finaliseRun(store, runID, time.Since(now), chaos.OutcomeCrashed,
					fmt.Sprintf("sqlite-busy holder: %v", err), note)
				return fmt.Errorf("chaos: sqlite-busy holder: %w", err)
			}
			dim.Println("  sqlite write lock held by sibling connection")
		}

		var ballast *chaos.DiskFullSimulator
		if ftype == chaos.FaultDiskFull {
			// Default to a small 16 MiB ballast unless the user passed a
			// numeric note; treats `--note 64m` as "64 MiB", `--note 1g` as
			// "1 GiB". Keeps the CLI flexible without adding another flag.
			size := parseBallastSize(note, 16<<20)
			ballast = chaos.NewDiskFullSimulator(workDir, size)
			if err := ballast.Start(); err != nil {
				_ = controller.Clear()
				finaliseRun(store, runID, time.Since(now), chaos.OutcomeCrashed,
					fmt.Sprintf("ballast: %v", err), note)
				return fmt.Errorf("chaos: disk-full ballast: %w", err)
			}
			dim.Printf("  ballast file: %s (%d bytes)\n",
				filepath.Join(workDir, ".cloop", "chaos", "ballast"), size)
		}

		cleanup := func() {
			_ = controller.Clear()
			if holder != nil {
				holder.Stop()
			}
			if ballast != nil {
				_ = ballast.Stop()
			}
		}

		if !wait {
			dim.Printf("  --wait=false: returning immediately. Fault will expire on its own.\n")
			// Note: when --wait=false we deliberately do NOT clean up holder/
			// ballast because they live in this process. They are only used
			// when --wait=true. SQLite-busy and disk-full with --wait=false
			// rely on the file-watcher in any other cloop process; without a
			// holder, the sqlite-busy fault has no observable effect.
			if holder != nil || ballast != nil {
				color.New(color.FgYellow).Fprintln(os.Stderr,
					"note: --wait=false with sqlite-busy or disk-full leaves no in-process holder; the fault has no effect. Use --wait=true.")
			}
			return nil
		}

		// Wait either for the fault duration or for SIGINT/SIGTERM, whichever
		// comes first. Cleanup runs unconditionally.
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		select {
		case <-time.After(duration):
		case <-ctx.Done():
			dim.Println("  interrupted — clearing fault")
		}

		cleanup()
		elapsed := time.Since(now)
		finaliseRun(store, runID, elapsed, chaos.OutcomeRecovered,
			"fault window closed cleanly", note)

		color.New(color.FgGreen, color.Bold).Printf("done in %s\n", elapsed.Round(time.Millisecond))
		return nil
	},
}

var chaosClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all currently-injected faults",
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		c := chaos.NewController(workDir)
		if err := c.Clear(); err != nil {
			return err
		}
		color.New(color.FgGreen).Println("All chaos faults cleared.")
		return nil
	},
}

var chaosListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show currently-active chaos faults",
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		c := chaos.NewController(workDir)
		_ = c.Refresh()
		active := c.Active()
		if len(active) == 0 {
			fmt.Println("no active faults")
			return nil
		}
		header := color.New(color.FgCyan, color.Bold)
		header.Println("Active faults")
		fmt.Println()
		for _, f := range active {
			fmt.Printf("  %-22s  expires %s  probability=%.2f  %s\n",
				f.Type, f.Until.Format(time.RFC3339),
				orOne(f.Probability), f.Note)
		}
		return nil
	},
}

var chaosReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Summarise how the system handled each fault",
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		workDir, _ := os.Getwd()
		dbPath := filepath.Join(workDir, ".cloop", "state.db")

		store, err := chaos.OpenStore(dbPath)
		if err != nil {
			return err
		}
		defer store.Close()

		runs, err := store.List(0, limit)
		if err != nil {
			return err
		}
		header := color.New(color.FgCyan, color.Bold)
		header.Printf("cloop chaos report — last %d runs\n", limit)
		fmt.Println()
		fmt.Println(chaos.FormatSummary(chaos.SummaryRows(runs)))
		if len(runs) > 0 {
			fmt.Println("Recent runs:")
			for _, r := range runs {
				fmt.Printf("  %s  %-22s  %-9s  %5dms  %s\n",
					r.StartedAt.UTC().Format("2006-01-02 15:04:05Z"),
					r.FaultType,
					r.Outcome,
					r.DurationMS,
					r.OutcomeDetail,
				)
			}
		}
		return nil
	},
}

var chaosSuiteCmd = &cobra.Command{
	Use:   "suite",
	Short: "Run the built-in chaos test suite against this project",
	Long: `Run every fault type sequentially and probe the system's response.

The default suite uses in-process probes (HTTP via chaos.Transport, sqlite
busy holder, disk simulator) so it is safe to run without a live cloop
daemon. Each probe is short — a full suite run finishes in well under a
minute.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		clearAfter, _ := cmd.Flags().GetBool("clear-after")
		workDir, _ := os.Getwd()
		dbPath := filepath.Join(workDir, ".cloop", "state.db")

		store, err := chaos.OpenStore(dbPath)
		if err != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr,
				"warning: could not open chaos_runs store (%v) — running suite without persistence\n", err)
		}
		if store != nil {
			defer store.Close()
		}

		controller := chaos.NewController(workDir)
		prev := chaos.SetGlobal(controller)
		defer chaos.SetGlobal(prev)

		header := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)
		header.Println("cloop chaos suite")
		fmt.Println()

		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		s := &chaos.Suite{
			WorkDir:    workDir,
			StatePath:  dbPath,
			Controller: controller,
			Store:      store,
			Cases:      chaos.DefaultCases(workDir),
		}

		runs, err := s.Run(ctx)
		if err != nil {
			return err
		}
		if clearAfter {
			_ = controller.Clear()
		}

		for _, r := range runs {
			marker := color.New(color.FgGreen).Sprint("✓")
			if r.Outcome != chaos.OutcomeRecovered {
				marker = color.New(color.FgRed).Sprint("✗")
			}
			fmt.Printf("  %s %-22s %-9s %5dms %s\n",
				marker, r.FaultType, r.Outcome, r.DurationMS, r.OutcomeDetail)
		}
		fmt.Println()
		dim.Println(chaos.FormatSummary(chaos.SummaryRows(runs)))
		return nil
	},
}

// finaliseRun stamps the chaos_runs row with the observed outcome. Best-effort
// — a closed store is silently ignored so CLI errors are not double-reported.
func finaliseRun(store *chaos.Store, id int64, elapsed time.Duration, outcome chaos.Outcome, detail, note string) {
	if store == nil || id == 0 {
		return
	}
	_ = store.Update(chaos.Run{
		ID:            id,
		StoppedAt:     time.Now(),
		DurationMS:    elapsed.Milliseconds(),
		Outcome:       outcome,
		OutcomeDetail: detail,
		Note:          note,
	})
}

// parseBallastSize parses notes like "64m" or "1g" into a byte count.
// Returns def when the note is empty or unparseable.
func parseBallastSize(note string, def int64) int64 {
	if note == "" {
		return def
	}
	multiplier := int64(1)
	last := note[len(note)-1]
	body := note
	switch last {
	case 'k', 'K':
		multiplier = 1 << 10
		body = note[:len(note)-1]
	case 'm', 'M':
		multiplier = 1 << 20
		body = note[:len(note)-1]
	case 'g', 'G':
		multiplier = 1 << 30
		body = note[:len(note)-1]
	}
	var n int64
	if _, err := fmt.Sscanf(body, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n * multiplier
}

// orOne returns p if positive, else 1.0. Keeps the list output legible when
// older mirror files have probability=0 (which the controller treats as 1.0).
func orOne(p float64) float64 {
	if p <= 0 {
		return 1.0
	}
	return p
}
