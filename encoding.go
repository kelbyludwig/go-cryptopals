package encoding

import "fmt"
import "encoding/hex"
import "encoding/base64"
import "os"

func HexToBase64(hexstring string) string {
    bytes,err := hex.DecodeString(hexstring)
    if err != nil {
        fmt.Println("[ERR] HexToBase64 failed.")
        panic(err)
    }
    return base64.StdEncoding.EncodeToString(bytes)
}

func Base64ToHex(basestring string) string {
    bytes,err := base64.StdEncoding.DecodeString(basestring)
    if err != nil {
        fmt.Println("[ERR] Base64ToHex failed.")
        panic(err)
    }
    return hex.EncodeString(bytes)
}
