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

package campfire

import "testing"

func TestCampfireURI(t *testing.T) {
	uri := "camp://9d4e8faba9a93ef397554dc4:hLxK4U49l6fcZLH0@a.relay.metered.ca/?fingerprint#abcdefghijklmnopqrstuvwx12345678"
	campfire, err := ParseCampfireURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	encoded := campfire.EncodeURI()
	if encoded != uri {
		t.Fatalf("Expected %s, got %s", uri, encoded)
	}
}
