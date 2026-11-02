package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/chat"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	planChatMessage  string
	planChatHistory  string
	planChatProvider string
	planChatModel    string
	planChatTimeout  time.Duration
	planChatJSON     bool
	// planChatRequirements is the hub's requirement status summary (Task
	// 20463).
	planChatRequirements string
)

// planChatToken is one streamed piece of the answer.
type planChatToken struct {
	Token string `json:"token"`
}

// planChatAnswer is the finished answer `cloop plan chat --json` reports
// after its tokens.
type planChatAnswer struct {
	Answer string `json:"answer"`
}

// planChatCmd answers one question about the plan with the whole plan as
// context — the dashboard's plan assistant (Task 200). The hub dispatches it to
// the project's executor rather than calling the model itself (Task 20442), and
// relays the answer as it arrives: with --json each piece the provider streams
// is written as a framed chunk line (clijson.EmitChunk), and the whole answer
// as the final frame, which is all a provider that does not stream produces.
// Hidden: the conversation arrives as an argument, which is the hub's job to
// build.
var planChatCmd = &cobra.Command{
	Use:    "chat",
	Short:  "Internal: answer one question about the plan, for the dashboard's assistant",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		fail := func(err error) error {
			if planChatJSON {
				return failFramed(err)
			}
			return err
		}
		workdir, _ := os.Getwd()
		msg := strings.TrimSpace(planChatMessage)
		if msg == "" {
			return fail(fmt.Errorf("--message is required"))
		}
		var history []chat.PlanMessage
		if strings.TrimSpace(planChatHistory) != "" {
			if err := json.Unmarshal([]byte(planChatHistory), &history); err != nil {
				return fail(fmt.Errorf("--history is not a JSON list of {role, content}: %w", err))
			}
		}

		// A project with no state yet still gets an answer, as the dashboard's
		// always did: the prompt says there is no plan.
		s, _ := state.Load(workdir)
		prov, model, err := helperProvider(workdir, s, planChatProvider, planChatModel)
		if err != nil {
			return fail(fmt.Errorf("provider: %w", err))
		}
		// Where the requirements stand (Task 20463): the hub's summary, or
		// the project's own when it has one — a proposal says which
		// requirements each task it proposes covers.
		system := chat.PlanSystemPrompt(s)
		given := cmd.Flags().Changed("requirements")
		if given || s != nil {
			var plan *pm.Plan
			if s != nil {
				plan = s.Plan
			}
			reqs, err := plannerRequirementStatus(workdir, plan, planChatRequirements, given)
			if err != nil {
				// Answered without it: the question does not depend on it.
				fmt.Fprintf(os.Stderr, "warning: the requirement status is unreadable, answering without it: %v\n", err)
			} else {
				system += "\n" + reqs.Section() + reqs.ChatRules()
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), planChatTimeout)
		defer cancel()
		// A provider may hand tokens over on a goroutine of its own.
		var streamed atomic.Bool
		opts := provider.Options{
			Model:        model,
			SystemPrompt: system,
			WorkDir:      workdir,
			Timeout:      planChatTimeout,
			OnToken: func(token string) {
				if token == "" {
					return
				}
				streamed.Store(true)
				if planChatJSON {
					_ = clijson.EmitChunk(os.Stdout, planChatToken{Token: token})
					return
				}
				fmt.Print(token)
			},
		}
		res, err := prov.Complete(ctx, chat.PlanConversation(history, msg), opts)
		if err != nil {
			return fail(err)
		}
		answer := ""
		if res != nil {
			answer = res.Output
		}
		if planChatJSON {
			return clijson.Emit(os.Stdout, planChatAnswer{Answer: answer})
		}
		if !streamed.Load() {
			fmt.Print(answer)
		}
		fmt.Println()
		return nil
	},
}

func init() {
	planChatCmd.Flags().StringVar(&planChatMessage, "message", "", "The question to answer")
	planChatCmd.Flags().StringVar(&planChatHistory, "history", "", "Earlier turns, as a JSON list of {role, content}")
	planChatCmd.Flags().StringVar(&planChatProvider, "provider", "", "AI provider to use (default: the project's)")
	planChatCmd.Flags().StringVar(&planChatModel, "model", "", "Model override for the AI provider")
	planChatCmd.Flags().DurationVar(&planChatTimeout, "timeout", 2*time.Minute, "Timeout for the model call")
	planChatCmd.Flags().BoolVar(&planChatJSON, "json", false, "Stream framed chunks and report the answer as framed JSON, for the hub")
	planChatCmd.Flags().StringVar(&planChatRequirements, "requirements", "", "The requirement status summary, as JSON (the hub's)")
	planCmd.AddCommand(planChatCmd)
}
