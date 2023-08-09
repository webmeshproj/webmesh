package common

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// ParseFlagsAndSetupLogger is a helper function for setting up loggers for examples.
func ParseFlagsAndSetupLogger() *slog.Logger {
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			switch strings.ToLower(*logLevel) {
			case "debug":
				return slog.LevelDebug
			case "info":
				return slog.LevelInfo
			case "warn":
				return slog.LevelWarn
			case "error":
				return slog.LevelError
			default:
				fmt.Fprintln(os.Stderr, "invalid log level")
				os.Exit(1)
			}
			return slog.LevelInfo
		}(),
	}))
	slog.SetDefault(log)
	return log
}
