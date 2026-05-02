package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/checkpoint"
	"github.com/blechschmidt/cloop/pkg/env"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var taskExecRecord bool

var taskExecCmd = &cobra.Command{
	Use:   "exec <task-id> -- <command> [args...]",
	Short: "Run a shell command in the context of a task and record its output",
	Long: `Run an arbitrary shell command scoped to a specific task.

The command inherits the current environment plus task-specific variables:
  CLOOP_TASK_ID     – numeric task ID
  CLOOP_TASK_TITLE  – task title
  CLOOP_TASK_STATUS – current task status

Variables defined in .cloop/env.yaml are also injected (secrets decoded).

Combined stdout+stderr is captured and appended as a checkpoint history entry
for the task so it can be inspected later with 'cloop task checkpoint-diff'.
When --record is true (the default), an artifact file is also written to
.cloop/tasks/ for retrieval via 'cloop replay'.

Use '--' to separate cloop flags from the command and its own flags:

  cloop task exec 3 -- go test ./...
  cloop task exec 5 -- make build
  cloop task exec 7 --record=false -- echo hello`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}
		cmdArgs := args[1:]

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		var taskTitle, taskStatus string
		var taskFound bool
		for _, t := range s.Plan.Tasks {
			if t.ID == taskID {
				taskTitle = t.Title
				taskStatus = string(t.Status)
				taskFound = true
				break
			}
		}
		if !taskFound {
			return fmt.Errorf("task %d not found", taskID)
		}

		// Load .cloop/env.yaml secrets (non-fatal if missing).
		envVars, envErr := env.Load(workdir)
		if envErr != nil {
			color.New(color.Faint).Fprintf(os.Stderr, "warning: could not load .cloop/env.yaml: %v\n", envErr)
		}

		// Build process environment: inherit current env, overlay project vars,
		// then inject task-specific vars last so they always take precedence.
		procEnv := append(os.Environ(), env.EnvLines(envVars)...)
		procEnv = append(procEnv,
			fmt.Sprintf("CLOOP_TASK_ID=%d", taskID),
			"CLOOP_TASK_TITLE="+taskTitle,
			"CLOOP_TASK_STATUS="+taskStatus,
		)

		// Run the command, streaming output to the terminal while also capturing
		// combined stdout+stderr into a buffer for checkpoint/artifact storage.
		var buf bytes.Buffer
		c := exec.Command(cmdArgs[0], cmdArgs[1:]...) //nolint:gosec
		c.Env = procEnv
		c.Stdin = os.Stdin
		c.Stdout = &teeWriter{dst: os.Stdout, buf: &buf}
		c.Stderr = &teeWriter{dst: os.Stderr, buf: &buf}

		color.New(color.FgCyan, color.Bold).Printf("Running for task %d [%s]: %s\n", taskID, taskStatus, taskTitle)
		color.New(color.Faint).Printf("Command: %v\n\n", cmdArgs)

		startTime := time.Now()
		runErr := c.Run()
		elapsed := time.Since(startTime)

		exitCode := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}

		fmt.Println()
		if exitCode == 0 {
			color.New(color.FgGreen).Printf("Exit code: 0  (elapsed: %s)\n", elapsed.Round(time.Millisecond))
		} else {
			color.New(color.FgRed).Printf("Exit code: %d  (elapsed: %s)\n", exitCode, elapsed.Round(time.Millisecond))
		}

		combined := buf.String()

		// Append a checkpoint history entry with event="exec".
		cp := &checkpoint.Checkpoint{
			TaskID:            taskID,
			TaskTitle:         taskTitle,
			AccumulatedOutput: combined,
			StartTimestamp:    startTime,
			Event:             "exec",
			Status:            taskStatus,
			ElapsedSec:        elapsed.Seconds(),
			Timestamp:         time.Now(),
		}
		if saveErr := checkpoint.SaveHistoryEntry(workdir, cp); saveErr != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "warning: could not save checkpoint entry: %v\n", saveErr)
		} else {
			color.New(color.Faint).Printf("Checkpoint saved for task %d.\n", taskID)
		}

		// Write artifact file when --record is enabled (default true).
		if taskExecRecord {
			for _, t := range s.Plan.Tasks {
				if t.ID == taskID {
					if relPath, artErr := artifact.WriteExecArtifact(workdir, t, cmdArgs, exitCode, elapsed, combined); artErr != nil {
						color.New(color.FgYellow).Fprintf(os.Stderr, "warning: could not write artifact: %v\n", artErr)
					} else {
						color.New(color.Faint).Printf("Artifact: %s\n", relPath)
					}
					break
				}
			}
		}

		return nil
	},
}

// teeWriter writes to dst while also appending to buf.
type teeWriter struct {
	dst *os.File
	buf *bytes.Buffer
}

func (t *teeWriter) Write(p []byte) (int, error) {
	t.buf.Write(p) // best-effort capture; error intentionally ignored
	return t.dst.Write(p)
}

func init() {
	taskExecCmd.Flags().BoolVar(&taskExecRecord, "record", true, "Persist output as an artifact file in .cloop/tasks/")
}
