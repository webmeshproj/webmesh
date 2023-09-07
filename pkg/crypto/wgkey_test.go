package crypto

import "testing"

func TestWireGuardKeySign(t *testing.T) {
	key := MustGenerateKeyV2()
	data := []byte("hello world")
	sig, err := key.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := key.GetPublic().Verify(data, sig); err != nil {
		t.Fatal(err)
	} else if !valid {
		t.Errorf("signature did not verify")
	}
}
