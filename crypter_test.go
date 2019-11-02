package main

import (
	"testing"
)

var (
	key        = "!@#lrx00"
	descrypted = "password"
	encrypted  = "0c9Us6gTzYiz8KvrUExCZg=="
)

func TestDesCBCEncrypt(t *testing.T) {
	actual, err := DesCBCEncrypt(descrypted, []byte(key))
	if err != nil {
		t.Error(err)
	}
	if actual != encrypted {
		t.Errorf("DesCBCEncrypt(%s) = %s, but expected %s ", descrypted, actual, encrypted)
	}
}

func TestDesCBCDecrypt(t *testing.T) {
	actual, err := DesCBCDecrypt(encrypted, []byte(key))
	if err != nil {
		t.Error(err)
	}
	if actual != descrypted {
		t.Errorf("DesCBCDecrypt(%s) = %s, but expected %s ", encrypted, actual, descrypted)
	}
}
