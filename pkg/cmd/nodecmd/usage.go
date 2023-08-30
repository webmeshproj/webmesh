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

package nodecmd

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/pflag"
)

var configPrefixes = []string{
	"global",
	"bootstrap",
	"auth",
	"mesh",
	"raft",
	"services",
	"tls",
	"wireguard",
	"discovery",
}

func Usage(fs *pflag.FlagSet) string {
	var sb strings.Builder
	sb.WriteString("Usage: webmesh-node [options]\n\n")

	// Write a short description of the nodecmd.
	sb.WriteString(`webmesh-node is a node in a webmesh cluster. It can be used to run services and join a mesh.

Configurations are passed via configuration files, environment variables, and command line flags.
The order of precedence for parsing is:

1. Files
2. Environment variables
3. Command line flags
`)

	t := tabwriter.NewWriter(&sb, 1, 4, 4, ' ', 0)
	for _, prefix := range configPrefixes {
		// Capitalize the prefix and write a description of the section.
		_, _ = t.Write([]byte(fmt.Sprintf("\n%s Options:\n\n", strings.ToTitle(prefix))))
		fs.VisitAll(func(f *pflag.Flag) {
			if strings.HasPrefix(f.Name, prefix) {
				line := fmt.Sprintf("\t--%s=%s\t\t%s", f.Name, f.DefValue, f.Usage)
				_, _ = t.Write([]byte(line))
				_, _ = t.Write([]byte("\n"))
			}
		})
	}

	t.Flush()

	// Write out the footer.

	sb.WriteString("\nMiscellaneous Options:\n\n")
	fs.VisitAll(func(f *pflag.Flag) {
		for _, p := range configPrefixes {
			if strings.HasPrefix(f.Name, p) || strings.HasPrefix(f.Name, "bridge") {
				return
			}
		}
		line := fmt.Sprintf("\t--%s\t\t%s", f.Name, f.Usage)
		_, _ = t.Write([]byte(line))
		_, _ = t.Write([]byte("\n"))
	})
	t.Flush()

	return sb.String()
}
