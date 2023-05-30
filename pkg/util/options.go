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

package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// DecodeOptions will attempt to decode the given reader into the given object.
// The formatHint is used to select the format of the document. If the formatHint
// is empty, the format is guessed from the document. The document is first
// treated as a go-template with some custom functions. This allows us to use
// environment variables and file contents in the config.
func DecodeOptions(in io.ReadCloser, formatHint string, out any) error {
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	// We first treat the data as a go-template with some custom functions.
	// This allows us to use environment variables and file contents in the config.
	// We then decode the data into the given object.
	t := template.New("config").Funcs(template.FuncMap{
		"env": func(key string) string {
			return os.Getenv(key)
		},
		"file": func(path string) string {
			data, err := os.ReadFile(path)
			if err != nil {
				return ""
			}
			return string(data)
		},
	})
	t, err = t.Parse(string(data))
	if err != nil {
		return fmt.Errorf("parse config template: %w", err)
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, nil)
	if err != nil {
		return fmt.Errorf("execute config template: %w", err)
	}
	data = buf.Bytes()
	// Now we decode the data into the given object.
	var format string
	switch formatHint {
	case "yaml", "yml":
		format = "yaml"
	case "json":
		format = "json"
	case "toml":
		format = "toml"
	default:
		format = detectFormat(data)
	}
	var decode func([]byte, any) error
	switch format {
	case "yaml":
		decode = yaml.Unmarshal
	case "json":
		decode = json.Unmarshal
	case "toml":
		decode = toml.Unmarshal
	}
	return decode(data, out)
}

func detectFormat(data []byte) string {
	if len(data) > 0 && data[0] == '{' {
		return "json"
	}
	if len(data) > 0 && (data[0] == '[') {
		return "toml"
	}
	// We gotta guess.
	err := toml.Unmarshal(data, &struct{}{})
	if err == nil {
		return "toml"
	}
	// All JSON documents are valid YAML documents,
	// So we'll just assume it's YAML if it's not TOML.
	return "yaml"
}
