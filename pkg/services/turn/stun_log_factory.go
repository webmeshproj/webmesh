/*
Copyright 2023.

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

package turn

import (
	"fmt"

	"github.com/pion/logging"
	"golang.org/x/exp/slog"
)

type loggerFactory struct {
	*slog.Logger
}

func (f *loggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return &slogLogger{f.Logger.With(slog.String("scope", scope))}
}

type slogLogger struct{ *slog.Logger }

func (l *slogLogger) Trace(msg string) {
	l.Logger.Debug(msg)
}

func (l *slogLogger) Tracef(format string, args ...interface{}) {
	l.Logger.Debug(fmt.Sprintf(format, args...))
}

func (l *slogLogger) Debug(msg string) {
	l.Logger.Debug(msg)
}

func (l *slogLogger) Debugf(format string, args ...interface{}) {
	l.Logger.Debug(fmt.Sprintf(format, args...))
}

func (l *slogLogger) Info(msg string) {
	l.Logger.Info(msg)
}

func (l *slogLogger) Infof(format string, args ...interface{}) {
	l.Logger.Info(fmt.Sprintf(format, args...))
}

func (l *slogLogger) Warn(msg string) {
	l.Logger.Warn(msg)
}

func (l *slogLogger) Warnf(format string, args ...interface{}) {
	l.Logger.Warn(fmt.Sprintf(format, args...))
}

func (l *slogLogger) Error(msg string) {
	l.Logger.Error(msg)
}

func (l *slogLogger) Errorf(format string, args ...interface{}) {
	l.Logger.Error(fmt.Sprintf(format, args...))
}
