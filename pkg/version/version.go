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

// Package version contains compile-time version information.
package version

import "encoding/json"

var (
	// Version is the version of the binary.
	Version = "unknown"
	// GitCommit is the git commit of the binary.
	GitCommit = "unknown"
	// BuildDate is the date the binary was built.
	BuildDate = "unknown"
)

// BuildInfo is the current build information.
type BuildInfo struct {
	Version   string `json:"version"`
	GitCommit string `json:"gitCommit"`
	BuildDate string `json:"buildDate"`
}

// GetBuildInfo returns the current build information.
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
	}
}

// MarshalJSON implements json.Marshaler.
func (b BuildInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"version":   b.Version,
		"gitCommit": b.GitCommit,
		"buildDate": b.BuildDate,
	})
}

// PrettyJSON returns the current build information as a pretty-printed JSON string.
func (b BuildInfo) PrettyJSON(component string) string {
	out, _ := json.MarshalIndent(map[string]string{
		"component": component,
		"version":   b.Version,
		"gitCommit": b.GitCommit,
		"buildDate": b.BuildDate,
	}, "", "    ")
	return string(out)
}
