package encoding

import "fmt"
import "encoding/hex"
import "encoding/base64"


//Hex to <X> functions
func HexToBase64(hexstring string) string {
    bytes := HexToBytes(hexstring)
    return base64.StdEncoding.EncodeToString(bytes)
}

func HexToBytes(hexstring string) []byte {
    bytes,err := hex.DecodeString(hexstring)
    if err != nil {
        fmt.Println("[ERR] HexToBytes failed.")
        panic(err)
    }
    return bytes
}

//Base64 to <X> functions
func Base64ToHex(basestring string) string {
    bytes,err := base64.StdEncoding.DecodeString(basestring)
    if err != nil {
        fmt.Println("[ERR] Base64ToHex failed.")
        panic(err)
    }
    return hex.EncodeToString(bytes)
}

//Bytes to <X> functions
func BytesToHex(bs []byte) string {
    return hex.EncodeToString(bs)
}
