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

package util

import (
	"fmt"
	"log/slog"

	"github.com/pion/logging"
)

type STUNLoggerFactory struct {
	*slog.Logger
}

func NewSTUNLoggerFactory(logger *slog.Logger) *STUNLoggerFactory {
	return &STUNLoggerFactory{logger}
}

func (f *STUNLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return &slogSTUNLogger{f.Logger.With(slog.String("scope", scope))}
}

type slogSTUNLogger struct{ *slog.Logger }

func (l *slogSTUNLogger) Trace(msg string) {
	l.Logger.Debug(msg)
}

func (l *slogSTUNLogger) Tracef(format string, args ...interface{}) {
	l.Logger.Debug(fmt.Sprintf(format, args...))
}

func (l *slogSTUNLogger) Debug(msg string) {
	l.Logger.Debug(msg)
}

func (l *slogSTUNLogger) Debugf(format string, args ...interface{}) {
	l.Logger.Debug(fmt.Sprintf(format, args...))
}

func (l *slogSTUNLogger) Info(msg string) {
	l.Logger.Info(msg)
}

func (l *slogSTUNLogger) Infof(format string, args ...interface{}) {
	l.Logger.Info(fmt.Sprintf(format, args...))
}

func (l *slogSTUNLogger) Warn(msg string) {
	l.Logger.Warn(msg)
}

func (l *slogSTUNLogger) Warnf(format string, args ...interface{}) {
	l.Logger.Warn(fmt.Sprintf(format, args...))
}

func (l *slogSTUNLogger) Error(msg string) {
	l.Logger.Error(msg)
}

func (l *slogSTUNLogger) Errorf(format string, args ...interface{}) {
	l.Logger.Error(fmt.Sprintf(format, args...))
}
