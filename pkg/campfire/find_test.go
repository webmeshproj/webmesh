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

func FuzzFindCampFire(f *testing.F) {
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
		resp1, err := FindCampFire(psk, testTURNServers)
		if err != nil {
			t.Skip(err)
		}
		resp2, err := FindCampFire(psk, testTURNServers)
		if err != nil {
			t.Skip(err)
		}
		if resp1.Secret != resp2.Secret {
			t.Fatalf("expected %q, got %q", resp1.Secret, resp2.Secret)
		}
		if resp1.TURNServer != resp2.TURNServer {
			t.Fatalf("expected %q, got %q", resp1.TURNServer, resp2.TURNServer)
		}
	})
}

var testTURNServers = []string{
	"stun.voipdiscount.com:3478",
	"stun.ladridiricette.it:3478",
	"stun.tel2.co.uk:3478",
	"stun.counterpath.com:3478",
	"stun.gmx.net:3478",
	"stun.commpeak.com:3478",
	"stun3.l.google.com:19305",
	"stun.wifirst.net:3478",
	"stun.romaaeterna.nl:3478",
	"stun.teliax.com:3478",
	"stun.istitutogramscisiciliano.it:3478",
	"stun.voipbuster.com:3478",
	"stun.nfon.net:3478",
	"stun.deepfinesse.com:3478",
	"stun.thebrassgroup.it:3478",
	"stun.mobile-italia.com:3478",
	"stun.dcalling.de:3478",
	"stun.halonet.pl:3478",
	"stun.openvoip.it:3478",
	"stun.mywatson.it:3478",
	"stun.bitburger.de:3478",
	"stun.eol.co.nz:3478",
	"stun.comrex.com:3478",
	"stun.sipdiscount.com:3478",
	"stun.siptrunk.com:3478",
	"stun.telbo.com:3478",
	"stun.ipfire.org:3478",
	"stun.graftlab.com:3478",
	"stun.cellmail.com:3478",
	"stun.medvc.eu:3478",
	"stun.romancecompass.com:3478",
	"stun.lleida.net:3478",
	"stun.rynga.com:3478",
	"stun.ekiga.net:3478",
	"stun.url.net.au:3478",
	"stun.hide.me:3478",
}
