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

package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows/svc/debug"
)

func NewServiceLogAdapter(l debug.Log, logLevel string) *slog.Logger {
	return slog.New(&ServiceLogHandler{
		log:      l,
		logLevel: logLevel,
	})
}

type ServiceLogHandler struct {
	log      debug.Log
	group    string
	attrs    []slog.Attr
	logLevel string
}

func (s *ServiceLogHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	current := func() slog.Level {
		switch strings.ToLower(s.logLevel) {
		case "debug":
			return slog.LevelDebug
		case "info":
			return slog.LevelInfo
		case "warn":
			return slog.LevelWarn
		case "error":
			return slog.LevelError
		default:
			return slog.LevelInfo
		}
	}()
	return lvl >= current
}

func (s *ServiceLogHandler) Handle(ctx context.Context, record slog.Record) error {
	msg := fmt.Sprintf("[%s]\t%s\t%s", record.Time.String(), record.Level.String(), record.Message)
	if s.group != "" {
		msg = s.group + ": " + msg
	}
	for _, attr := range s.attrs {
		msg += " " + attr.Key + "=" + attr.Value.String()
	}
	switch record.Level {
	case slog.LevelDebug:
		s.log.Info(1, msg)
	case slog.LevelInfo:
		s.log.Info(1, msg)
	case slog.LevelWarn:
		s.log.Warning(1, msg)
	case slog.LevelError:
		s.log.Error(1, msg)
	}
	return nil
}

func (s *ServiceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ServiceLogHandler{
		log:      s.log,
		group:    s.group,
		attrs:    append(s.attrs, attrs...),
		logLevel: s.logLevel,
	}
}

func (s *ServiceLogHandler) WithGroup(name string) slog.Handler {
	return &ServiceLogHandler{
		log:      s.log,
		group:    name,
		attrs:    s.attrs,
		logLevel: s.logLevel,
	}
}
