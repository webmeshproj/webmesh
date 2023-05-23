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
	"encoding/json"
	"io"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// DecodeOptions will attempt to decode the given reader into the given object.
// The formatHint is used to select the format of the document. If the formatHint
// is empty, the format is guessed from the document.
func DecodeOptions(in io.Reader, formatHint string, out any) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
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
