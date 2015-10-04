package xor

import "os"
import "fmt"

func Xor(a, b []byte) []byte {
    if len(a) != len(b) {
        fmt.Println("[ERR] Xor failed: lengths are not equal.")
        os.Exit(1)
    }

    var c []byte = make([]byte, len(a))
    for i,_ := range a {
        c[i] = a[i] ^ b[i]
    }
    return c
}

func AllBytes() []byte {
    var i byte
    var is []byte = make([]byte, 255)
    for i = 0; i < 255; i++ {
        is[int(i)] = byte(i)
    }
    return is
}

func SingleCharXor(key byte, plaintext []byte) []byte {
    ct := make([]byte, len(plaintext))
    for i,b := range plaintext {
        ct[i] = b ^ key
    }
    return ct
}

func RepeatingKeyXor(key []byte, plaintext []byte) []byte {
    var ciphertext []byte = make([]byte, len(plaintext))
    for i,_ := range plaintext {
        ciphertext[i] = key[i % len(key)] ^ plaintext[i]
    }
    return ciphertext
}
