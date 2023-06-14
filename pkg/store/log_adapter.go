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

package store

import (
	"context"
	"io"
	"log"

	"github.com/hashicorp/go-hclog"
	"golang.org/x/exp/slog"
)

var _ hclog.Logger = (*hclogAdapter)(nil)

type hclogAdapter struct {
	*slog.Logger
	name  string
	level string
}

func (h *hclogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	switch level {
	case hclog.Trace, hclog.Debug:
		h.Logger.Debug(msg, args...)
	case hclog.Info:
		h.Logger.Info(msg, args...)
	case hclog.Warn:
		h.Logger.Warn(msg, args...)
	case hclog.Error:
		h.Logger.Error(msg, args...)
	case hclog.Off:
		// no-op
	}
}

// Name returns the name of the logger.
func (h *hclogAdapter) Name() string {
	return h.name
}

// With returns a new Logger that has this logger's context plus the given key
// value pairs.
func (h *hclogAdapter) With(args ...interface{}) hclog.Logger {
	return &hclogAdapter{
		Logger: h.Logger.With(args...),
		name:   h.name,
		level:  h.level,
	}
}

// Named returns a new Logger that prefixes all messages with the given name.
func (h *hclogAdapter) Named(name string) hclog.Logger {
	return &hclogAdapter{
		Logger: h.Logger.With("component", name),
		name:   h.name,
		level:  h.level,
	}
}

// ResetNamed returns a new Logger that prefixes all messages with the given name.
func (h *hclogAdapter) ResetNamed(name string) hclog.Logger {
	return &hclogAdapter{
		Logger: h.Logger.With("component", name),
		name:   name,
		level:  h.level,
	}
}

// Returns the current level
func (h *hclogAdapter) GetLevel() hclog.Level {
	return hclog.LevelFromString(h.level)
}

// Updates the level. This should affect all related loggers as well,
// unless they were created with IndependentLevels. If an
// implementation cannot update the level on the fly, it should no-op.
func (h *hclogAdapter) SetLevel(level hclog.Level) {
	h.level = level.String()
}

// ImpliedArgs returns With key/value pairs
func (h *hclogAdapter) ImpliedArgs() []interface{} {
	return nil
}

// Trace aliases to Debug
func (h *hclogAdapter) Trace(msg string, args ...interface{}) {
	h.Log(hclog.Trace, msg, args...)
}

// Indicate if TRACE logs would be emitted.
func (h *hclogAdapter) IsTrace() bool {
	return h.Logger.Handler().Enabled(context.Background(), slog.LevelDebug)
}

// Indicate if DEBUG logs would be emitted.
func (h *hclogAdapter) IsDebug() bool {
	return h.Logger.Handler().Enabled(context.Background(), slog.LevelDebug)
}

// Indicate if INFO logs would be emitted.
func (h *hclogAdapter) IsInfo() bool {
	return h.Logger.Handler().Enabled(context.Background(), slog.LevelInfo)
}

// Indicate if WARN logs would be emitted.
func (h *hclogAdapter) IsWarn() bool {
	return h.Logger.Handler().Enabled(context.Background(), slog.LevelWarn)
}

// Indicate if ERROR logs would be emitted.
func (h *hclogAdapter) IsError() bool {
	return h.Logger.Handler().Enabled(context.Background(), slog.LevelError)
}

// Return a value that conforms to the stdlib log.Logger interface
func (h *hclogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	return log.New(h.StandardWriter(opts), "", 0)
}

// Return a value that conforms to io.Writer, which can be passed into log.SetOutput()
func (h *hclogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return &logWriter{log: h.Logger}
}

type logWriter struct {
	log *slog.Logger
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	lw.log.Info(string(p))
	return len(p), nil
}
