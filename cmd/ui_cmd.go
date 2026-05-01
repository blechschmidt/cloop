package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	uiPort   int
	uiNoBrowser bool
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Start a local web dashboard for monitoring and controlling cloop",
	Long: `Start a local web server that serves a real-time dashboard on http://localhost:8080.

The dashboard shows the project goal, status, step history with outputs,
task list (PM mode), live progress via SSE, and run/stop controls.

  cloop ui                  # start on default port 8080
  cloop ui --port 9090      # use a custom port
  cloop ui --no-browser     # don't open the browser automatically`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		if !uiNoBrowser {
			go openBrowser("http://localhost:" + strconv.Itoa(uiPort))
		}

		srv := ui.New(workdir, uiPort)
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
	rootCmd.AddCommand(uiCmd)
}
