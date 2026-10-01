// Command mcpstub mimics the sectool MCP server startup for orchestrator
// tests. The mode comes from MCPSTUB_MODE: ready (200 on /mcp), notfound (404
// on /mcp), ignore-term (200 but SIGTERM ignored), hang (never listens),
// crash (exit 3 immediately).
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// skip the leading subcommand so flag.Parse sees the flags
	var flags []string
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		}
	}
	port := flag.Int("port", 0, "")
	flag.Int("proxy-port", 0, "")
	flag.String("workflow", "", "")
	_ = flag.CommandLine.Parse(flags)

	switch os.Getenv("MCPSTUB_MODE") {
	case "crash":
		os.Exit(3)
	case "hang":
		time.Sleep(time.Hour)
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, _ *http.Request) {
		if os.Getenv("MCPSTUB_MODE") == "notfound" {
			http.NotFound(w, nil)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", *port), Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}
