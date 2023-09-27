/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package logging contains logging utilities and adapters for various logging
// libraries.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// SetupLogging sets up logging for the application.
func SetupLogging(logLevel string) *slog.Logger {
	log := NewLogger(logLevel)
	slog.SetDefault(log)
	return log
}

// NewLogger returns a new logger with the given log level.
// If log level is empty or "silent" then the logger will be silent.
func NewLogger(logLevel string) *slog.Logger {
	if logLevel == "" || strings.ToLower(logLevel) == "silent" {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			switch strings.ToLower(logLevel) {
			case "debug":
				return slog.LevelDebug
			case "info":
				return slog.LevelInfo
			case "warn":
				return slog.LevelWarn
			case "error":
				return slog.LevelError
			default:
				slog.Default().Warn("Invalid log level specified, defaulting to info", "log-level", logLevel)
			}
			return slog.LevelInfo
		}(),
	}))
	return log
}
