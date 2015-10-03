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
