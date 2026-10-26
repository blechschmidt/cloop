package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	reviseInstruction string
	reviseDescription string
	reviseTitle       string
	reviseProvider    string
	reviseModel       string
	reviseTimeout     time.Duration
	reviseJSON        bool
)

// reviseResult is what `cloop task revise --json` reports.
type reviseResult struct {
	Description string `json:"description"`
	Provider    string `json:"provider"`
	Model       string `json:"model"`
}

// taskReviseCmd applies a dictated instruction to a task's details and prints
// the revision, saving nothing. It is the dashboard's Revise (Task 20302),
// which the hub dispatches to the project's executor rather than calling the
// model itself (Task 20442) — so it is hidden: the editor's draft arrives as an
// argument, which is the hub's job to build.
var taskReviseCmd = &cobra.Command{
	Use:    "revise <id>",
	Short:  "Internal: apply a dictated instruction to a task's details, saving nothing",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fail := func(err error) error {
			if reviseJSON {
				return failFramed(err)
			}
			return err
		}
		workdir, _ := os.Getwd()
		id, err := strconv.Atoi(args[0])
		if err != nil || id <= 0 {
			return fail(fmt.Errorf("invalid task ID %q", args[0]))
		}
		instruction := pm.TruncateRunes(strings.TrimSpace(reviseInstruction), pm.MaxReviseInstructionRunes)
		if instruction == "" {
			return fail(fmt.Errorf("--instruction is required: nothing was said to apply"))
		}
		current := pm.TruncateRunes(strings.TrimSpace(reviseDescription), pm.MaxReviseDescriptionRunes)
		if current == "" {
			return fail(fmt.Errorf("--description is required: there are no details to revise"))
		}

		s, err := state.Load(workdir)
		if err != nil {
			return fail(err)
		}
		if s.Plan == nil {
			return fail(fmt.Errorf("no task plan found — run cloop init first"))
		}
		task, err := s.RequireTask(id)
		if err != nil {
			return fail(err)
		}
		// The draft's title is the one meant, as in the hub; the stored one is
		// the fallback.
		title := pm.TruncateRunes(strings.TrimSpace(reviseTitle), pm.MaxReviseInstructionRunes)
		if title == "" {
			title = task.Title
		}

		prov, model, err := helperProvider(workdir, s, reviseProvider, reviseModel)
		if err != nil {
			return fail(fmt.Errorf("provider: %w", err))
		}
		ctx, cancel := context.WithTimeout(context.Background(), reviseTimeout)
		defer cancel()
		res, err := prov.Complete(ctx, pm.RevisePrompt(title, current, instruction), provider.Options{
			Model:   model,
			WorkDir: workdir,
			Timeout: reviseTimeout,
		})
		if err != nil {
			return fail(err)
		}
		// A provider that returns no error and no result is a bug in that
		// provider, but it would crash this command rather than the one with
		// the bug.
		revised := ""
		if res != nil {
			revised = pm.CleanRevisedDescription(res.Output)
		}
		if reviseJSON {
			// An empty answer is reported as one: the hub refuses it in its own
			// words, and must refuse it anyway, whatever cloop sent it.
			return clijson.Emit(os.Stdout, reviseResult{Description: revised, Provider: prov.Name(), Model: model})
		}
		if revised == "" {
			return fmt.Errorf("the model returned nothing to apply")
		}
		fmt.Println(revised)
		return nil
	},
}

func init() {
	taskReviseCmd.Flags().StringVar(&reviseInstruction, "instruction", "", "What was said: the change to apply")
	taskReviseCmd.Flags().StringVar(&reviseDescription, "description", "", "The details to revise (the editor's draft)")
	taskReviseCmd.Flags().StringVar(&reviseTitle, "title", "", "The draft's title, for context (default: the task's)")
	taskReviseCmd.Flags().StringVar(&reviseProvider, "provider", "", "AI provider to use (default: the project's)")
	taskReviseCmd.Flags().StringVar(&reviseModel, "model", "", "Model override for the AI provider")
	taskReviseCmd.Flags().DurationVar(&reviseTimeout, "timeout", 90*time.Second, "Timeout for the model call")
	taskReviseCmd.Flags().BoolVar(&reviseJSON, "json", false, "Report the revision as framed JSON, for the hub")
	taskCmd.AddCommand(taskReviseCmd)
}
