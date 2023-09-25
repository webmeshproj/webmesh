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

// Package buffers contains facilities for changing system buffer sizes.
package buffers

// SetMaximumReadBuffer sets the maximum read buffer size.
func SetMaximumReadBuffer(val int) error {
	return setMaxReadBuffer(val)
}

// SetMaximumWriteBuffer sets the maximum write buffer size.
func SetMaximumWriteBuffer(val int) error {
	return setMaxWriteBuffer(val)
}
