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
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// FlagsUsage prints the usage of all flags with the given prefix.
func FlagsUsage(title, prefix, notPrefix string) {
	t := tabwriter.NewWriter(os.Stderr, 1, 4, 4, ' ', 0)
	defer t.Flush()
	fmt.Fprintf(t, "%s\n\n", title)
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if !strings.HasPrefix(f.Name, prefix) {
			return
		}
		if notPrefix != "" {
			if strings.HasPrefix(f.Name, notPrefix) {
				return
			}
		}
		usageLines := strings.Split(f.Usage, "\n")
		if len(usageLines) > 1 {
			fmt.Fprintln(t)
		}
		if f.DefValue == "" {
			fmt.Fprintf(t, "\t--%s\t\t%s\n", f.Name, usageLines[0])
		} else {
			fmt.Fprintf(t, "\t--%s\t(default: %s)\t%s\n", f.Name, f.DefValue, usageLines[0])
		}
		if len(usageLines) == 1 {
			return
		}
		for _, line := range usageLines[1:] {
			fmt.Fprintf(t, "\t\t\t%s\n", line)
		}
		fmt.Fprintln(t)
	})
	fmt.Fprintf(t, "\n")
}
