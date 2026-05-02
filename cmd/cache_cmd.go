package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/cache"
	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the AI response cache",
}

var cacheStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show cache hit rate and entry count",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		c, err := cache.New(workdir, 0, 0)
		if err != nil {
			return fmt.Errorf("opening cache: %w", err)
		}
		s := c.Stats()
		fmt.Printf("Entries : %d\n", s.Entries)
		fmt.Printf("Hits    : %d\n", s.Hits)
		fmt.Printf("Misses  : %d\n", s.Misses)
		if s.Hits+s.Misses > 0 {
			fmt.Printf("Hit rate: %.1f%%\n", s.HitRate*100)
		} else {
			fmt.Println("Hit rate: n/a (no requests yet)")
		}
		return nil
	},
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove all cached responses",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		c, err := cache.New(workdir, 0, 0)
		if err != nil {
			return fmt.Errorf("opening cache: %w", err)
		}
		before := c.Stats()
		if err := c.Clear(); err != nil {
			return fmt.Errorf("clearing cache: %w", err)
		}
		fmt.Printf("Cleared %d cache entries.\n", before.Entries)
		return nil
	},
}

func init() {
	cacheCmd.AddCommand(cacheStatsCmd)
	cacheCmd.AddCommand(cacheClearCmd)
	rootCmd.AddCommand(cacheCmd)
}
