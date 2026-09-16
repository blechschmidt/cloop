package cmd

// `cloop hub limits` — capping one project's sandbox from a shell (Task 20301).
//
// The operator's half of a sentence the hub could previously only hear one side
// of. A project states what it needs in .cloop/sandbox.yaml; until this command
// existed there was nowhere to state what it may *have*, because that file is
// committed to the repository and so belongs to the people being limited.
//
// Unlike `cloop hub quota` next door, this one does not refuse while a hub is
// running. That command edits state the enforcer loads into memory once at
// startup, so a write behind a live hub would neither take effect nor survive
// the next edit from the panel. A resource ceiling is read from the database on
// every dispatch instead — the lookup is one indexed row against a run that is
// about to start a container — so a cap set here binds the next task to start,
// including on a hub that has been up for a month.

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
)

var hubLimitsCmd = &cobra.Command{
	Use:   "limits",
	Short: "Inspect and set per-project resource ceilings",
	Long: `Read and edit the ceilings that bound what one project's sandboxes may be given.

There are two ceilings and they compose by getting tighter:

  fleet    executors.limits in .cloop/config.yaml — every workload on this hub
  project  this command — one project, held below the fleet's allowance

Neither can be raised by the project. A project's own .cloop/sandbox.yaml states
what it needs and is capped by both, including when it states nothing at all —
an absent resources.memory means "no limit", so a ceiling that ignored it would
be defeated by deleting a line.

  cloop hub limits list                         both ceilings, and every capped project
  cloop hub limits set /srv/proj --memory 2g --reason "..."
  cloop hub limits clear /srv/proj --reason "..."

Ceilings are read on every dispatch, so an edit binds the next task to start —
no hub restart, and no refusal while one is running.`,
}

var hubLimitsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show the fleet ceiling and every per-project ceiling",
	Long: `List the fleet-wide ceiling and the projects that carry one of their own.

The fleet ceiling is read from this directory's .cloop/config.yaml. A project
with no row is bounded by the fleet ceiling alone; a project with a row is
bounded by whichever of the two is tighter, resource by resource.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()

		rows, err := db.ListProjectResourceLimits()
		if err != nil {
			return err
		}
		fleet := fleetCeilingFor(workdir)

		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"fleet":    fleet,
				"projects": rows,
			})
		}

		fmt.Printf("Fleet ceiling (executors.limits): %s\n\n", fleet.Describe())
		if len(rows) == 0 {
			fmt.Println("No project carries a ceiling of its own; the fleet ceiling applies to all.")
			fmt.Println(`Set one with "cloop hub limits set <project-path> --memory 2g --reason ..."`)
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PROJECT\tCPU\tMEMORY\tDISK\tPIDS\tSET BY")
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				truncateField(r.ProjectPath, 40),
				executor.FormatCPUMillis(r.Ceiling.CPUMillis),
				executor.FormatMB(r.Ceiling.MemoryMB),
				executor.FormatMB(r.Ceiling.DiskMB),
				pidsLabel(r.Ceiling.PIDs),
				truncateField(orDash(r.SetBy), 24))
		}
		return w.Flush()
	},
}

var hubLimitsSetCmd = &cobra.Command{
	Use:   "set <project-path>",
	Short: "Set or tighten one project's resource ceiling",
	Long: `Write a resource ceiling for one project.

The ceiling is sparse and merges with what is already stored: setting --memory
leaves an existing CPU cap alone. Pass a resource explicitly as 0 to uncap just
that one; use "clear" to remove the whole row.

Sizes take the same grammar as the rest of the executor config — "512m", "2g",
or a bare integer read as megabytes.

A ceiling above the fleet's is stored as written and has no effect while the
fleet ceiling is tighter, which is the containment property: a per-project
ceiling is a second bound, never a waiver.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectPath := args[0]
		workdir, _ := cmd.Flags().GetString("workdir")
		reason, _ := cmd.Flags().GetString("reason")
		if reason == "" {
			return fmt.Errorf("--reason is required; it is recorded in the audit trail")
		}

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		warnIfNotAHub(workdir)

		// Merge onto what is stored, so capping memory does not silently
		// release a CPU cap someone set last week.
		merged, _, err := db.ProjectResourceCeiling(projectPath)
		if err != nil {
			return err
		}
		changed := false
		// Flags().Changed is the discriminator between "not mentioned" and
		// "explicitly zero": the second is how an operator uncaps one resource
		// without touching the others, and a plain value check would read it as
		// the first and silently do nothing.
		if cmd.Flags().Changed("cpu") {
			v, _ := cmd.Flags().GetFloat64("cpu")
			if v < 0 {
				return fmt.Errorf("--cpu must be >= 0, got %v", v)
			}
			merged.CPUMillis, changed = int(v*1000), true
		}
		if cmd.Flags().Changed("memory") {
			s, _ := cmd.Flags().GetString("memory")
			mb, err := config.ParseMemoryMB(s)
			if err != nil {
				return fmt.Errorf("--memory: %w", err)
			}
			merged.MemoryMB, changed = mb, true
		}
		if cmd.Flags().Changed("disk") {
			s, _ := cmd.Flags().GetString("disk")
			mb, err := config.ParseDiskMB(s)
			if err != nil {
				return fmt.Errorf("--disk: %w", err)
			}
			merged.DiskMB, changed = mb, true
		}
		if cmd.Flags().Changed("pids") {
			v, _ := cmd.Flags().GetInt("pids")
			if v < 0 {
				return fmt.Errorf("--pids must be >= 0, got %d "+
					"(a ceiling cannot waive the process cap; pass 0 to uncap it)", v)
			}
			merged.PIDs, changed = v, true
		}
		if !changed {
			return fmt.Errorf("name at least one of --cpu, --memory, --disk or --pids")
		}
		if err := merged.Validate(); err != nil {
			return err
		}

		if err := auditHubAdmin(db, auditaction.ActionResourceCeilingSet,
			"project_resource_limit", projectPath, reason, map[string]any{
				"project":    projectPath,
				"cpu_millis": merged.CPUMillis,
				"memory_mb":  merged.MemoryMB,
				"disk_mb":    merged.DiskMB,
				"pids":       merged.PIDs,
			}); err != nil {
			return err
		}

		// Every resource ended up uncapped. Storing that would leave a row
		// claiming to bound nothing, which reads in the panel as a policy and
		// is the absence of one.
		if merged.IsZero() {
			if err := db.ClearProjectResourceLimit(projectPath); err != nil {
				return err
			}
			color.New(color.FgGreen).Printf("Every ceiling cleared for %s.\n", projectPath)
			return nil
		}
		if err := db.SetProjectResourceLimit(projectPath, merged, operatorActor()); err != nil {
			return err
		}
		color.New(color.FgGreen).Printf("Ceiling for %s: %s\n", projectPath, merged.Describe())

		// The fleet ceiling is the other half of what will actually be
		// enforced, and an operator who set 8g under a 2g fleet cap has not
		// been told anything false — just something that will not happen.
		if fleet := fleetCeilingFor(workdir); !fleet.IsZero() {
			if effective := fleet.Tighten(merged); effective != merged {
				fmt.Printf("Note: the fleet ceiling is tighter on some resources; "+
					"this project will get %s.\n", effective.Describe())
			}
		}
		return nil
	},
}

var hubLimitsClearCmd = &cobra.Command{
	Use:   "clear <project-path>",
	Short: "Remove one project's resource ceiling",
	Long: `Delete the stored ceiling for a project.

The project is then bounded by the fleet ceiling alone — which is not the same
as uncapped, unless executors.limits is also unset.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectPath := args[0]
		workdir, _ := cmd.Flags().GetString("workdir")
		reason, _ := cmd.Flags().GetString("reason")
		if reason == "" {
			return fmt.Errorf("--reason is required; it is recorded in the audit trail")
		}

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		warnIfNotAHub(workdir)

		if err := auditHubAdmin(db, auditaction.ActionResourceCeilingCleared,
			"project_resource_limit", projectPath, reason, map[string]any{
				"project": projectPath,
			}); err != nil {
			return err
		}
		if err := db.ClearProjectResourceLimit(projectPath); err != nil {
			return err
		}
		color.New(color.FgGreen).Printf("Cleared the ceiling for %s.\n", projectPath)
		if fleet := fleetCeilingFor(workdir); !fleet.IsZero() {
			fmt.Printf("It is still bounded by the fleet ceiling: %s\n", fleet.Describe())
		}
		return nil
	},
}

// fleetCeilingFor reads executors.limits from workdir's config.
//
// A config that cannot be read or parsed yields the zero ceiling, matching what
// the hub itself would install — the CLI must describe the policy actually in
// force, not the one the file was meant to express.
func fleetCeilingFor(workdir string) executor.ResourceCeiling {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return executor.ResourceCeiling{}
		}
		workdir = wd
	}
	cfg, err := config.Load(workdir)
	if err != nil || cfg == nil {
		return executor.ResourceCeiling{}
	}
	ceiling, err := cfg.Executors.Limits.Ceiling()
	if err != nil {
		return executor.ResourceCeiling{}
	}
	return ceiling
}

// pidsLabel renders a process cap, spelling out the uncapped case rather than
// printing a bare 0 that reads as "no processes allowed".
func pidsLabel(pids int) string {
	if pids <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", pids)
}

func init() {
	for _, c := range []*cobra.Command{hubLimitsListCmd, hubLimitsSetCmd, hubLimitsClearCmd} {
		c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: cwd)")
	}
	hubLimitsListCmd.Flags().Bool("json", false, "emit JSON instead of a table")
	for _, c := range []*cobra.Command{hubLimitsSetCmd, hubLimitsClearCmd} {
		c.Flags().String("reason", "", "why (required; recorded in the audit trail)")
	}
	hubLimitsSetCmd.Flags().Float64("cpu", 0, "core allowance ceiling (2 = two cores; 0 uncaps)")
	hubLimitsSetCmd.Flags().String("memory", "", `memory ceiling ("2g", "512m"; 0 uncaps)`)
	hubLimitsSetCmd.Flags().String("disk", "", `workspace and scratch ceiling ("10g"; 0 uncaps)`)
	hubLimitsSetCmd.Flags().Int("pids", 0, "process/thread ceiling (0 uncaps)")

	hubLimitsCmd.AddCommand(hubLimitsListCmd)
	hubLimitsCmd.AddCommand(hubLimitsSetCmd)
	hubLimitsCmd.AddCommand(hubLimitsClearCmd)
	hubCmd.AddCommand(hubLimitsCmd)
}
