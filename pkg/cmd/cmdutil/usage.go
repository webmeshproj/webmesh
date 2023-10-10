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

// Package cmdutil provides utilities for working with the command-line entrypoints.
package cmdutil

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/pflag"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// UsageConfig is the config for building a usage string.
type UsageConfig struct {
	// Name is the name of the command.
	Name string
	// Description is the description of the command.
	Description string
	// Prefixes is a list of flag prefixes to
	// break into sections in the usage string.
	Prefixes []string
	// Flagset is the flagset to use for the command.
	Flagset *pflag.FlagSet
	// SkipPrefixes is a list of prefixes to skip
	// when building the usage string.
	SkipPrefixes []string
}

// NewUsageFunc returns a function that returns a usage string.
func NewUsageFunc(cfg UsageConfig) func() {
	return func() {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Usage: %s [options]\n\n", cfg.Name))
		sb.WriteString(strings.TrimSpace(cfg.Description) + "\n")
		t := tabwriter.NewWriter(&sb, 2, 2, 2, '\t', 0)
		for _, prefix := range cfg.Prefixes {
			// Capitalize the prefix and write a description of the section.
			titleBytes := make([]byte, len(prefix))
			toReplace := strings.Replace(prefix, ".", " ", -1)
			_, _, _ = cases.Title(language.English).Transform(titleBytes, []byte(toReplace), true)
			_, _ = t.Write([]byte(fmt.Sprintf("\n%s Options:\n\n", string(titleBytes))))
			cfg.Flagset.VisitAll(func(f *pflag.Flag) {
				for _, sp := range cfg.SkipPrefixes {
					if strings.HasPrefix(f.Name, sp) {
						return
					}
				}
				if !strings.HasPrefix(f.Name, prefix) {
					return
				}
				// Make sure it doesn't match any other longer prefixes.
				for _, p := range cfg.Prefixes {
					if p == prefix {
						continue
					}
					if strings.HasPrefix(f.Name, p) && len(p) > len(prefix) {
						return
					}
				}
				line := fmt.Sprintf("\t--%s=%s\t\t%s", f.Name, f.DefValue, f.Usage)
				_, _ = t.Write([]byte(line))
				_, _ = t.Write([]byte("\n"))
				t.Flush()
			})
		}
		sb.WriteString("\nMiscellaneous Options:\n\n")
		cfg.Flagset.VisitAll(func(f *pflag.Flag) {
			for _, p := range cfg.Prefixes {
				if strings.HasPrefix(f.Name, p) {
					return
				}
				for _, sp := range cfg.SkipPrefixes {
					if strings.HasPrefix(f.Name, sp) {
						return
					}
				}
			}
			line := fmt.Sprintf("\t--%s\t\t%s", f.Name, f.Usage)
			_, _ = t.Write([]byte(line))
			_, _ = t.Write([]byte("\n"))
			t.Flush()
		})
		sb.WriteString("\n")
		t.Flush()
		fmt.Fprintln(os.Stderr, sb.String())
	}
}
