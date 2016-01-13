package rsa

import (
	"testing"
)

func TestImproperKeypairGen(t *testing.T) {
	_, err := GenerateKeyPair(0)
	if err == nil {
		t.Errorf("Failed to throw error with 0 bit keypair generation\n")
	}
	_, err = GenerateKeyPair(1023)
	if err == nil {
		t.Errorf("Failed to throw error with non-byte aligned bit keypair generation\n")
	}

}

func TestKeypairGen(t *testing.T) {
	keypair, err := GenerateKeyPair(1024)

	if err != nil {
		t.Errorf("Failed to generated keypair with error:\n%v\n", err)
	}

	t.Logf("KeyPair generation success! (%v, %v, %v)\n", keypair.Modulus, keypair.PrivateExp, keypair.PublicExp)
}
