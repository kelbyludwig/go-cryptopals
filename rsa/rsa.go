package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
)

type PublicKey struct {
	Modulus   *big.Int
	PublicExp *big.Int
}

type PrivateKey struct {
	Modulus    *big.Int
	PrivateExp *big.Int
}

type KeyPair struct {
	PublicKey  *PublicKey
	PrivateKey *PrivateKey
}

//GenerateKeyPair generates an RSA public/private keypair of size bits
//from a CSPRNG.
func GenerateKeyPair(bits int) (keypair *KeyPair, err error) {
	keypair = new(KeyPair)
	keypair.PublicKey = new(PublicKey)
	keypair.PrivateKey = new(PrivateKey)

	if bits == 0 {
		err = errors.New("RSA modulus size must not be zero.")
		return
	}
	if bits%8 != 0 {
		err = errors.New("RSA modulus size must be a multiple of 8.")
		return
	}

	for limit := 0; limit < 1000; limit++ {
		var tempKey *rsa.PrivateKey
		tempKey, err = rsa.GenerateKey(rand.Reader, bits)

		if err != nil {
			return
		}

		if len(tempKey.Primes) != 2 {
			err = errors.New("RSA package generated a weird set of primes (i.e. not two)")
			return
		}

		p := tempKey.Primes[0]
		q := tempKey.Primes[1]

		if p.Cmp(q) == 0 {
			err = errors.New("RSA keypair factors were equal. This is really unlikely dependent on the bitsize and it appears something horrible has happened.")
			return
		}
		if gcd := new(big.Int).GCD(nil, nil, p, q); gcd.Cmp(big.NewInt(1)) != 0 {
			err = errors.New("RSA primes were not relatively prime!")
			return
		}

		modulus := new(big.Int).Mul(p, q)

		publicExp := big.NewInt(3)
		//publicExp := big.NewInt(65537)

		//totient = (p-1) * (q-1)
		totient := new(big.Int)
		totient.Sub(p, big.NewInt(1))
		totient.Mul(totient, new(big.Int).Sub(q, big.NewInt(1)))

		if gcd := new(big.Int).GCD(nil, nil, publicExp, totient); gcd.Cmp(big.NewInt(1)) != 0 {
			continue
		}

		privateExp := new(big.Int).ModInverse(publicExp, totient)
		keypair.PublicKey.Modulus = modulus
		keypair.PrivateKey.Modulus = modulus
		keypair.PublicKey.PublicExp = publicExp
		keypair.PrivateKey.PrivateExp = privateExp
		return
	}
	err = errors.New("Failed to generate a within the limit!")
	return

}

func Encrypt(message []byte, publicKey *PublicKey) *big.Int {
	messageNum := new(big.Int).SetBytes(message)
	ciphertext := new(big.Int).Exp(messageNum, publicKey.PublicExp, publicKey.Modulus)
	return ciphertext
}

func Decrypt(ciphertext *big.Int, privateKey *PrivateKey) []byte {
	return new(big.Int).Exp(ciphertext, privateKey.PrivateExp, privateKey.Modulus).Bytes()
}
