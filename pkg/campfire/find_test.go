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

func FuzzFind(f *testing.F) {
	Now = func() time.Time {
		return time.Unix(0, 0)
	}
	testcases := []string{
		// Some randomly generated 32 byte PSKs.
		"E7gonE7TmwXJTaSzEkLqQx0Vcpimv0a0",
		"l5HKGoK5AtxIVcgQ3yt0KYFD9DoGxpPE",
		"LPsNrQxnFY43ob472fr0Um2fGKxweaTc",
		"l3AyEJ8n6O5X8ijMcFQZaCwqzZ1dmtmc",
		"LcNVwKa9qL4HFQ6l5a2DB56W6DtDV9PS",
		"QwjAUcrJKHpsEgA8jvFMcXd1urmIz8In",
		"8VfjHcidCz2tIKmGkJUqkeCuoREonZ3K",
		"2o5oeCTjRx1kpjhWhh6x3VMss5Z3Z3Z3",
		"aVk8MqqOJydjoruJhT+FbN9qjXFvk9Za",
		"R0kITeF6rXzNd9tqavra6szH9cRcJbGp",
	}
	for _, tc := range testcases {
		f.Add([]byte(tc))
	}
	f.Fuzz(func(t *testing.T, psk []byte) {
		resp1, err := Find(psk, nil)
		if err != nil {
			t.Skip(err)
		}
		resp2, err := Find(psk, nil)
		if err != nil {
			t.Skip(err)
		}
		if resp1.LocalSecret != resp2.LocalSecret {
			t.Fatalf("expected %q, got %q", resp1.LocalSecret, resp2.LocalSecret)
		}
		if resp1.RemoteSecret != resp2.RemoteSecret {
			t.Fatalf("expected %q, got %q", resp1.RemoteSecret, resp2.RemoteSecret)
		}
		if resp1.TURNServer != resp2.TURNServer {
			t.Fatalf("expected %q, got %q", resp1.TURNServer, resp2.TURNServer)
		}
	})
}
