package main

import "crypto/sha1"
import "bytes"
import "encoding/binary"
import "flag"
import "fmt"

func mac(key, message string) [20]byte {
    m := make([]byte, len(message))
    k := make([]byte, len(key))
    mac := append(k,m...)
    return sha1.Sum(mac)
}

func mac_verify(key, message string, given_mac [20]byte) bool {
    expected_mac := mac(key, message)
    if expected_mac != given_mac {
        return false
    } else {
        return true
    }
}

//Converts a uint64 to a byte array
func uint642bytes(in uint64) []byte {
    buf := new(bytes.Buffer)
    err := binary.Write(buf, binary.BigEndian, in)
    if err != nil {
        fmt.Println("[ERROR] Failed converting length to byte array!")
    }
    return buf.Bytes()
}

func pad_message(in string) []byte {
    //Length of input in bytes
    input := []byte(in)
    var ml_bytes uint64 = uint64(len(input))

    //Create initial internal state
    zero_padding := 55 - (ml_bytes % 64)
    zeros := make([]byte, zero_padding)
    state := make([]byte, ml_bytes)
    copy(state, input)
    state = append(state, '\x80')
    state = append(state, zeros...)
    state = append(state, uint642bytes(ml_bytes * 8)...)
    fmt.Println(state)
    return state
}


func main() {
    message := flag.String("m", "", "Message to authenticate")
    key := flag.String("k", "ayyyyyy... so secret!", "Key for SHA1-MAC")
    flag.Parse()
    pad_message(*message)
    expected_mac := mac(*key, *message)
    fmt.Println("VERIFY: ", mac_verify(*key, *message, expected_mac))
}

