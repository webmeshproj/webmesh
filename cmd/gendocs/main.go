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

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/spf13/cobra/doc"

	"github.com/webmeshproj/webmesh/pkg/cmd/ctlcmd"
	"github.com/webmeshproj/webmesh/pkg/cmd/nodecmd"
)

func main() {
	fs := flag.NewFlagSet("gendocs", flag.ExitOnError)
	out := fs.String("out", "", "Output for generated docs (directory for ctl, file for node)")
	ctldocs := fs.Bool("ctl", false, "Generate docs for ctl")
	nodedocs := fs.Bool("node", false, "Generate docs for node")
	if len(os.Args) < 2 {
		fs.Usage()
		os.Exit(1)
	}
	err := fs.Parse(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	if !*ctldocs && !*nodedocs {
		fs.Usage()
		fatal(errors.New("must specify -ctl or -node"))
	}
	if *out == "" {
		fs.Usage()
		fatal(errors.New("must specify -out"))
	}
	if *ctldocs {
		cmd := ctlcmd.Root()
		err := doc.GenMarkdownTree(cmd, *out)
		if err != nil {
			fatal(err)
		}
		return
	}
	err = nodecmd.GenMarkdownTree(*out)
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
	os.Exit(1)
}
