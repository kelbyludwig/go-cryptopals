package aes

import "fmt"
import "os"
import "crypto/aes"
import "github.com/kelbyludwig/cryptopals/xor"

func CBCEncrypt(key, iv, plaintext []byte) (ciphertext []byte) {
    for len(plaintext) > 0 {
        pt_block := plaintext[:16]
        intermediate_block := xor.Xor(iv, pt_block)
        ct_block := ECBEncrypt(key, intermediate_block)
        ciphertext = append(ciphertext, ct_block...)
        iv = ct_block
        plaintext = plaintext[16:]
    }
    return ciphertext
}

func CBCDecrypt(key, iv, ciphertext []byte) (plaintext []byte) {
    for len(ciphertext) > 0 {
        ct_block := ciphertext[:16]
        pt_block := ECBDecrypt(key, ct_block)
        pt_block = xor.Xor(iv, pt_block)
        plaintext = append(plaintext, pt_block...)
        iv = ct_block
        ciphertext = ciphertext[16:]
    }
    return plaintext
}


func ECBEncrypt(key, plaintext []byte) (ciphertext []byte) {
	block,err := aes.NewCipher(key)

	if err != nil {
		fmt.Println("ECBEncrypt: Error creating block.")
		os.Exit(1)
	}

	// s/o to agl: https://code.google.com/p/go/issues/detail?id=5597
	bs := block.BlockSize()
	if len(plaintext) % bs != 0 {
	    fmt.Println("ECBEncrypt: Need a multiple of the blocksize.")
		os.Exit(1)
	}

	for len(plaintext) > 0 {
        encblock := make([]byte, bs)
		block.Encrypt(encblock, plaintext)
        ciphertext = append(ciphertext, encblock...)
		plaintext = plaintext[bs:]
	}
	return ciphertext
}

func ECBDecrypt(key, ciphertext []byte) (plaintext []byte) {
	block,err := aes.NewCipher(key)

	if err != nil {
		fmt.Println("ECBDecrypt: Error creating block.")
		os.Exit(1)
	}

	// s/o to agl: https://code.google.com/p/go/issues/detail?id=5597
	bs := block.BlockSize()
	if len(ciphertext) % bs != 0 {
	    fmt.Println("ECBDecrypt: Need a multiple of the blocksize.")
		os.Exit(1)
	}

	for len(ciphertext) > 0 {
		decblock := make([]byte, bs)
		block.Decrypt(decblock, ciphertext)
		plaintext = append(plaintext, decblock...)
		ciphertext = ciphertext[bs:]
	}
	return plaintext
}

func Pad(input []byte, block_size int) []byte {
    l := len(input)
    pad_value := block_size % l
    if pad_value == 0 {
        pad_value = block_size
    }
    var padding []byte = make([]byte, pad_value)
    for i := 0; i < pad_value; i++ {
        padding[i] = byte(pad_value)
    }
    return append(input, padding...)
}
