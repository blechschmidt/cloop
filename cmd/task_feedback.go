package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/feedback"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	feedbackRating  int
	feedbackComment string
)

var taskFeedbackCmd = &cobra.Command{
	Use:   "feedback <task-id>",
	Short: "Record a human rating (1-5) for a task's AI output",
	Long: `Attach a human quality rating to a task's AI-generated output.

Ratings are stored in .cloop/feedback.jsonl as append-only JSONL records
containing the task ID, rating (1-5), optional comment, timestamp, and the
provider/model used for the task.

The ratings are surfaced by 'cloop task feedback list' and are used by the
adaptive prompt effectiveness system to weight future prompt selection.

Examples:
  cloop task feedback 3 --rating 5 --comment "Excellent, exactly what I needed"
  cloop task feedback 7 --rating 2 --comment "Too verbose, missed key edge cases"
  cloop task feedback list
  cloop task feedback list 3`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		if feedbackRating < 1 || feedbackRating > 5 {
			return fmt.Errorf("--rating must be between 1 and 5")
		}

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		var taskTitle, provider, model string
		if s.PMMode && s.Plan != nil {
			for _, t := range s.Plan.Tasks {
				if t.ID == taskID {
					taskTitle = t.Title
					break
				}
			}
		}
		if taskTitle == "" {
			taskTitle = fmt.Sprintf("task-%d", taskID)
		}
		provider = s.Provider
		model = s.Model

		rec := feedback.Record{
			TaskID:    taskID,
			TaskTitle: taskTitle,
			Rating:    feedbackRating,
			Comment:   feedbackComment,
			Provider:  provider,
			Model:     model,
		}

		if err := feedback.Append(workdir, rec); err != nil {
			return fmt.Errorf("saving feedback: %w", err)
		}

		stars := feedback.Stars(feedbackRating)
		color.New(color.FgGreen).Printf("Feedback recorded for task %d: %s %s\n", taskID, stars, taskTitle)
		if feedbackComment != "" {
			color.New(color.Faint).Printf("  Comment: %s\n", feedbackComment)
		}
		return nil
	},
}

var taskFeedbackListCmd = &cobra.Command{
	Use:   "list [task-id]",
	Short: "Show stored feedback records",
	Long: `List all human feedback entries. Optionally filter by task ID.

Examples:
  cloop task feedback list
  cloop task feedback list 5`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		taskID := 0
		if len(args) == 1 {
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid task ID %q: must be a number", args[0])
			}
			taskID = id
		}

		records, err := feedback.List(workdir, taskID)
		if err != nil {
			return fmt.Errorf("loading feedback: %w", err)
		}

		if len(records) == 0 {
			if taskID > 0 {
				fmt.Printf("No feedback found for task %d.\n", taskID)
			} else {
				fmt.Println("No feedback records found. Use 'cloop task feedback <id> --rating N' to add one.")
			}
			return nil
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		goodColor := color.New(color.FgGreen)
		badColor := color.New(color.FgRed)

		if taskID > 0 {
			headerColor.Printf("Feedback for task %d (%d record(s)):\n\n", taskID, len(records))
		} else {
			headerColor.Printf("All feedback records (%d):\n\n", len(records))
		}

		for _, r := range records {
			stars := feedback.Stars(r.Rating)
			ts := r.Timestamp.Format("2006-01-02 15:04:05")

			ratingLine := fmt.Sprintf("  [task %d] %s  %s", r.TaskID, stars, r.TaskTitle)
			if r.Rating >= 4 {
				goodColor.Println(ratingLine)
			} else if r.Rating <= 2 {
				badColor.Println(ratingLine)
			} else {
				fmt.Println(ratingLine)
			}

			metaParts := []string{ts}
			if r.Provider != "" {
				metaParts = append(metaParts, r.Provider)
				if r.Model != "" {
					metaParts[len(metaParts)-1] += "/" + r.Model
				}
			}
			dimColor.Printf("         %s\n", joinStrings(metaParts, "  ·  "))
			if r.Comment != "" {
				dimColor.Printf("         \"%s\"\n", r.Comment)
			}
			fmt.Println()
		}

		avg, count := feedback.AvgRating(records)
		if count > 0 {
			avgStars := feedback.Stars(int(avg + 0.5))
			dimColor.Printf("  Average: %s  (%.1f / 5 across %d rating(s))\n", avgStars, avg, count)
		}
		return nil
	},
}

func init() {
	taskFeedbackCmd.Flags().IntVar(&feedbackRating, "rating", 0, "Quality rating from 1 (poor) to 5 (excellent) [required]")
	taskFeedbackCmd.Flags().StringVar(&feedbackComment, "comment", "", "Optional free-text comment")
	_ = taskFeedbackCmd.MarkFlagRequired("rating")

	taskFeedbackCmd.AddCommand(taskFeedbackListCmd)
	taskCmd.AddCommand(taskFeedbackCmd)
}

