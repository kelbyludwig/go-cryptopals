package rsa

import (
	"testing"
)

//func TestPrimeGeneration(t *testing.T) {
//	for i := 0; i < 100; i++ {
//		p, err := GenerateBigPrime(512 / 8)
//		if err != nil {
//			t.Errorf("Failed to generate big prime!\n")
//			return
//		}
//		if !p.ProbablyPrime(25) {
//			t.Errorf("GenerateBigPrime returned a non-prime number\n")
//			return
//		}
//	}
//}

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
	_, err := GenerateKeyPair(1024)

	if err != nil {
		t.Errorf("Failed to generate keypair with error:\n%v\n", err)
	}
}

func TestKeypairGenReliablility(t *testing.T) {
	for i := 0; i < 100; i++ {
		_, err := GenerateKeyPair(1024)
		if err != nil {
			t.Errorf("Failed to complete 100 error-free iterations of keygen. Failed at iteration %v.\n", i)
		}
	}
}

func TestEncryptionAndDecryption(t *testing.T) {

	keypair, err := GenerateKeyPair(1024)
	if err != nil {
		t.Errorf("Failed to generate keypair with error:\n%v\n", err)
		return
	}
	message := []byte{42}
	ciphertext := Encrypt(message, keypair.PublicKey)
	result := Decrypt(ciphertext, keypair.PrivateKey)

	if message[0] != result[0] || len(result) != 1 {
		t.Errorf("Failed to properly decrypt encrypted data.")
		return
	}

}
