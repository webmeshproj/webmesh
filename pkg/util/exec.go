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
	"os/exec"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func Exec(ctx context.Context, command string, args ...string) error {
	log := context.LoggerFrom(ctx)
	cmd := exec.CommandContext(ctx, command, args...)
	log.Debug(command, slog.String("args", strings.Join(args, " ")))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", command, args, err, out)
	}
	return nil
}

func ExecOutput(ctx context.Context, command string, args ...string) ([]byte, error) {
	log := context.LoggerFrom(ctx)
	cmd := exec.CommandContext(ctx, command, args...)
	log.Debug(command, slog.String("args", strings.Join(args, " ")))
	return cmd.CombinedOutput()
}
