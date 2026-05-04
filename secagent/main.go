package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-appsec/secagent/cli"
	"github.com/go-appsec/secagent/config"
	"github.com/go-appsec/secagent/orchestrator"
)

func main() {
	cfg, err := config.Parse(flag.CommandLine, os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	if cli.IsTerminal(os.Stderr) && os.Getenv("NO_COLOR") == "" {
		cli.EnableColors()
	}

	log, err := orchestrator.NewLogger(cfg.LogFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "log open: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sd := orchestrator.NewShutdown(ctx, log)

	// three-stage Ctrl+C / SIGTERM: verify-only, dump unvalidated, kill
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		var n int
		for range sig {
			n++
			switch n {
			case 1:
				_, _ = fmt.Fprintln(os.Stderr, "Ctrl+C — finishing verification of pending candidates. Press again to dump unvalidated. Press a third time to kill.")
				sd.RequestVerifyOnly()
			case 2:
				_, _ = fmt.Fprintln(os.Stderr, "Ctrl+C (2/3) — dumping unvalidated candidates. Press once more to kill.")
				sd.RequestDumpUnvalidated()
			default:
				_, _ = fmt.Fprintln(os.Stderr, "Ctrl+C (3/3) — killing.")
				sd.RequestKill()
				_ = log.Close()
				os.Exit(130)
			}
		}
	}()

	if err := orchestrator.Run(ctx, cfg, log, sd); err != nil {
		log.Log("controller", "fatal", map[string]any{"err": err.Error()})
		_, _ = fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}
