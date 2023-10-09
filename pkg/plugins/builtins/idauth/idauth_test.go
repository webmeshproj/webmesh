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

package idauth

import (
	"bytes"
	"testing"
	"time"
)

func TestCurrentSigData(t *testing.T) {
	t.Parallel()
	Now = func() time.Time {
		return time.Unix(0, 0)
	}
	c := Config{TimeSkew: 0}
	sigData := c.CurrentSigData("test")
	if len(sigData) != 1 {
		t.Fatalf("expected sigData to be 1 elements, got %d", len(sigData))
	}
	if !bytes.Equal(sigData[0], []byte("test:0")) {
		t.Errorf("expected sigData to be test:0, got %s", sigData[0])
	}

	c = Config{TimeSkew: 1}
	sigData = c.CurrentSigData("test")
	if len(sigData) != 3 {
		t.Fatalf("expected sigData to be 3 elements, got %d", len(sigData))
	}
	if !bytes.Equal(sigData[0], []byte("test:0")) {
		t.Errorf("expected sigData to be test:0, got %s", sigData[0])
	}
	if !bytes.Equal(sigData[1], []byte("test:-30")) {
		t.Errorf("expected sigData to be test:-30, got %s", sigData[1])
	}
	if !bytes.Equal(sigData[2], []byte("test:30")) {
		t.Errorf("expected sigData to be test:30, got %s", sigData[2])
	}

	c = Config{TimeSkew: 2}
	sigData = c.CurrentSigData("test")
	if len(sigData) != 5 {
		t.Fatalf("expected sigData to be 5 elements, got %d", len(sigData))
	}
	if !bytes.Equal(sigData[0], []byte("test:0")) {
		t.Errorf("expected sigData to be test:0, got %s", sigData[0])
	}
	if !bytes.Equal(sigData[1], []byte("test:-30")) {
		t.Errorf("expected sigData to be test:-30, got %s", sigData[1])
	}
	if !bytes.Equal(sigData[2], []byte("test:30")) {
		t.Errorf("expected sigData to be test:30, got %s", sigData[2])
	}
	if !bytes.Equal(sigData[3], []byte("test:-60")) {
		t.Errorf("expected sigData to be test:-60, got %s", sigData[3])
	}
	if !bytes.Equal(sigData[4], []byte("test:60")) {
		t.Errorf("expected sigData to be test:60, got %s", sigData[4])
	}
}
