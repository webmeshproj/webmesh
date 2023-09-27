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
	"fmt"
	"log/slog"

	"github.com/dgraph-io/badger/v4"
)

type badgerLogAdapter struct {
	*slog.Logger
}

// NewBadgerLogger returns a badger log adapter backed by slog with the given
// log level.
func NewBadgerLogger(logLevel string) badger.Logger {
	return NewBadgerAdapter(NewLogger(logLevel))
}

// NewBadgerAdapter returns a badger log adapter for the given logger.
func NewBadgerAdapter(logger *slog.Logger) badger.Logger {
	return &badgerLogAdapter{Logger: logger}
}

func (l *badgerLogAdapter) Errorf(format string, args ...any) {
	l.Error(fmt.Sprintf(format, args...))
}

func (l *badgerLogAdapter) Warningf(format string, args ...any) {
	l.Error(fmt.Sprintf(format, args...))
}

func (l *badgerLogAdapter) Infof(format string, args ...any) {
	l.Info(fmt.Sprintf(format, args...))
}

func (l *badgerLogAdapter) Debugf(format string, args ...any) {
	l.Debug(fmt.Sprintf(format, args...))
}
