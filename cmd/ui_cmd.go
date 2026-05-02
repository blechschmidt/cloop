package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	uiPort      int
	uiNoBrowser bool
	uiToken     string
	uiProjects  []string
	uiScan      string
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Start a local web dashboard for monitoring and controlling cloop",
	Long: `Start a local web server that serves a real-time dashboard on http://localhost:8080.

The dashboard shows the project goal, status, step history with outputs,
task list (PM mode), live progress via SSE, and run/stop controls.

  cloop ui                            # single-project mode (cwd)
  cloop ui --port 9090                # use a custom port
  cloop ui --no-browser               # don't open the browser automatically
  cloop ui --projects /a /b /c        # multi-project overview dashboard
  cloop ui --scan /root/Projects      # auto-discover cloop projects under dir`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		token := uiToken
		if token == "" {
			token = os.Getenv("CLOOP_UI_TOKEN")
		}

		// Resolve project list from --projects and/or --scan flags.
		var projectPaths []string
		projectPaths = append(projectPaths, uiProjects...)
		if uiScan != "" {
			scanned, err := multiui.Scan(uiScan)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: scan %s: %v\n", uiScan, err)
			} else {
				projectPaths = append(projectPaths, scanned...)
			}
		}

		// Persist newly discovered projects into the registry.
		if len(projectPaths) > 0 {
			if err := multiui.AddPaths(projectPaths); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not save project registry: %v\n", err)
			}
		}

		if !uiNoBrowser {
			go openBrowser("http://localhost:" + strconv.Itoa(uiPort))
		}

		srv := ui.New(workdir, uiPort, token)
		srv.Projects = projectPaths
		return srv.Start()
	},
}

// openBrowser opens the given URL in the default system browser.
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open browser: %v\n", err)
	}
}

func init() {
	uiCmd.Flags().IntVar(&uiPort, "port", 8080, "Port to listen on")
	uiCmd.Flags().BoolVar(&uiNoBrowser, "no-browser", false, "Do not open the browser automatically")
	uiCmd.Flags().StringVar(&uiToken, "token", "", "Auth token (also reads CLOOP_UI_TOKEN env var); if set, all API requests must supply it")
	uiCmd.Flags().StringArrayVar(&uiProjects, "projects", nil, "Additional project directories to include in the multi-project dashboard")
	uiCmd.Flags().StringVar(&uiScan, "scan", "", "Scan this directory for cloop projects and add them to the dashboard")
	rootCmd.AddCommand(uiCmd)
}
