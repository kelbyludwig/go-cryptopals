package rsa

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type KeyPair struct {
	Modulus    *big.Int
	PublicExp  *big.Int
	PrivateExp *big.Int
}

func GenerateBigPrime(bytes uint) (p *big.Int, err error) {
	p = new(big.Int)
	bytesBuffer := make([]byte, bytes)
	for {
		_, err = rand.Read(bytesBuffer)
		if err != nil {
			return
		}
		p.SetBytes(bytesBuffer)
		if p.ProbablyPrime(20) {
			err = nil
			return
		}
	}
}

//GenerateKeyPair generates an RSA public/private keypair of size bits
//from a CSPRNG.
func GenerateKeyPair(bits uint) (keypair *KeyPair, err error) {
	keypair = new(KeyPair)
	if bits == 0 {
		err = errors.New("RSA modulus size must not be zero.")
		return
	}
	if bits%8 != 0 {
		err = errors.New("RSA modulus size must be a multiple of 8.")
		return
	}

	//Divide by 16 so the multiple of p and q is parameter "bits" bits large.
	bytes := bits / 16

	p, _ := GenerateBigPrime(bytes)
	q, err := GenerateBigPrime(bytes)
	if err != nil {
		return
	}
	if p.Cmp(q) == 0 {
		err = errors.New("RSA keypair factors were equal. This is really unlikely dependent on the bitsize and it appears something horrible has happened.")
		return
	}
	modulus := new(big.Int).Mul(p, q)
	publicExp := big.NewInt(65537)

	//totient = (p-1) * (q-1)
	totient := new(big.Int)
	totient.Sub(p, big.NewInt(1))
	totient.Mul(totient, new(big.Int).Sub(q, big.NewInt(1)))

	privateExp := new(big.Int).ModInverse(totient, modulus)

	keypair.Modulus = modulus
	keypair.PublicExp = publicExp
	keypair.PrivateExp = privateExp
	return
}
