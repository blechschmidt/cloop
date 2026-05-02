package pm

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseCron validates a standard 5-field cron expression.
// Format: "min hour dom mon dow" (e.g. "0 9 * * 1" = every Monday at 09:00).
// Supports: numbers, *, ranges (1-5), lists (1,2,3), step values (*/5, 1-10/2).
func ParseCron(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("cron: expected 5 fields (min hour dom mon dow), got %d", len(fields))
	}
	type bounds struct{ min, max int }
	limits := []bounds{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	names := []string{"minute", "hour", "day-of-month", "month", "day-of-week"}
	for i, f := range fields {
		if err := validateCronField(f, limits[i].min, limits[i].max, names[i]); err != nil {
			return err
		}
	}
	return nil
}

func validateCronField(field string, min, max int, name string) error {
	for _, part := range strings.Split(field, ",") {
		if err := validateCronPart(part, min, max, name); err != nil {
			return err
		}
	}
	return nil
}

func validateCronPart(part string, min, max int, name string) error {
	step := 0
	if idx := strings.Index(part, "/"); idx >= 0 {
		var err error
		step, err = strconv.Atoi(part[idx+1:])
		if err != nil || step < 1 {
			return fmt.Errorf("cron: invalid step in %s field: %q", name, part)
		}
		part = part[:idx]
	}
	if part == "*" {
		return nil
	}
	if idx := strings.Index(part, "-"); idx >= 0 {
		lo, err1 := strconv.Atoi(part[:idx])
		hi, err2 := strconv.Atoi(part[idx+1:])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("cron: invalid range in %s field: %q", name, part)
		}
		if lo < min || hi > max || lo > hi {
			return fmt.Errorf("cron: range %d-%d out of bounds [%d-%d] in %s field", lo, hi, min, max, name)
		}
		_ = step
		return nil
	}
	n, err := strconv.Atoi(part)
	if err != nil {
		return fmt.Errorf("cron: invalid value in %s field: %q", name, part)
	}
	// day-of-week: 7 is an alias for Sunday (0)
	if name == "day-of-week" && n == 7 {
		return nil
	}
	if n < min || n > max {
		return fmt.Errorf("cron: value %d out of bounds [%d-%d] in %s field", n, min, max, name)
	}
	return nil
}

// matchCronField returns true if v matches the comma-separated cron field.
func matchCronField(field string, v int) bool {
	for _, part := range strings.Split(field, ",") {
		if matchCronPart(part, v) {
			return true
		}
	}
	return false
}

func matchCronPart(part string, v int) bool {
	step := 0
	if idx := strings.Index(part, "/"); idx >= 0 {
		step, _ = strconv.Atoi(part[idx+1:])
		part = part[:idx]
	}

	if part == "*" {
		if step > 0 {
			return v%step == 0
		}
		return true
	}

	var lo, hi int
	if idx := strings.Index(part, "-"); idx >= 0 {
		lo, _ = strconv.Atoi(part[:idx])
		hi, _ = strconv.Atoi(part[idx+1:])
	} else {
		n, _ := strconv.Atoi(part)
		// day-of-week: treat 7 as Sunday (0)
		if n == 7 {
			n = 0
		}
		lo, hi = n, n
	}

	if v < lo || v > hi {
		return false
	}
	if step > 0 {
		return (v-lo)%step == 0
	}
	return true
}

// NextTrigger computes the next time strictly after `from` that matches the
// cron expression. Advances minute by minute up to 4 years forward.
// Returns a zero Time if no match is found (should never happen for valid expressions).
func NextTrigger(expr string, from time.Time) time.Time {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Time{}
	}
	fMin, fHour, fDom, fMon, fDow := fields[0], fields[1], fields[2], fields[3], fields[4]

	// Start at the next full minute after `from`.
	t := from.Add(time.Minute).Truncate(time.Minute)
	end := from.Add(4 * 366 * 24 * time.Hour)

	for t.Before(end) {
		dow := int(t.Weekday()) // 0 = Sunday
		if matchCronField(fMon, int(t.Month())) &&
			matchCronField(fDom, t.Day()) &&
			matchCronField(fDow, dow) &&
			matchCronField(fHour, t.Hour()) &&
			matchCronField(fMin, t.Minute()) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}

// ResetIfDue resets a recurring task to pending and advances NextRunAt when
// the task's recurrence schedule is due (NextRunAt <= now) and the task is
// in a terminal state (done, skipped, or failed).
//
// If NextRunAt is not yet set, it is computed and saved but the task is NOT
// reset yet — it will reset on the next call once the time arrives.
//
// Returns true if the task was reset to pending.
func ResetIfDue(task *Task, now time.Time) bool {
	if task.Recurrence == "" {
		return false
	}
	// Only auto-reset tasks in terminal states.
	if task.Status != TaskDone && task.Status != TaskSkipped && task.Status != TaskFailed {
		return false
	}
	// If NextRunAt is not initialised, compute it from now and store it.
	if task.NextRunAt == nil {
		next := NextTrigger(task.Recurrence, now)
		if next.IsZero() {
			return false
		}
		task.NextRunAt = &next
		return false
	}
	// Not yet due.
	if now.Before(*task.NextRunAt) {
		return false
	}
	// Due — reset and advance the schedule.
	task.Status = TaskPending
	task.Result = ""
	task.StartedAt = nil
	task.CompletedAt = nil
	next := NextTrigger(task.Recurrence, now)
	if !next.IsZero() {
		task.NextRunAt = &next
	}
	return true
}
