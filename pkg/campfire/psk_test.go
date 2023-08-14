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

import (
	"testing"
	"time"
)

func FuzzGeneratePSK(f *testing.F) {
	Now = func() time.Time {
		return time.Unix(0, 0)
	}
	testcases := []string{
		// Some randomly generated 32 byte PSKs.
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
		string(MustGeneratePSK()),
	}
	seenPSKs := make(map[string]struct{})
	for _, tc := range testcases {
		seenPSKs[tc] = struct{}{}
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, psk string) {
		newPSK, err := GeneratePSK()
		if err != nil {
			t.Fatal(err)
		}
		if string(newPSK) == psk {
			t.Fatal("duplicate PSK generated")
		}
		if _, ok := seenPSKs[string(newPSK)]; ok {
			t.Fatal("duplicate PSK generated")
		}
		seenPSKs[string(newPSK)] = struct{}{}
	})
}
