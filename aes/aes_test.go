package aes

import "github.com/kelbyludwig/cryptopals/encoding"
import "testing"
import "bufio"
import "fmt"
import "os"

//Test for Set 1 challenge 7
func TestAESDecrypt(t *testing.T) {
    key := []byte("YELLOW SUBMARINE")
    file,err := os.Open("../files/7.txt")
    if err != nil {
        fmt.Println("[ERR] AESDecrypt failed to open file.")
        os.Exit(1)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)

    var ciphertext []byte
    for scanner.Scan() {
        line := encoding.Base64ToBytes(scanner.Text())
        ciphertext = append(ciphertext, []byte(line)...)
    }
    if actual := ECBEncrypt(key, ECBDecrypt(key, ciphertext)); string(actual) != string(ciphertext) {
        t.Errorf("AESDecrypt: Decrypting and then encrypting failed!")
        t.Errorf("Actual:   %v\n", actual)
        t.Errorf("Expected: %v\n", ciphertext)
    }
}

//Test for Set 2 challenge 1
func TestPad(t *testing.T) {
    input := []byte("YELLOW SUBMARINE")
    result := string(Pad(input, 20))
    expected_result := "YELLOW SUBMARINE\x04\x04\x04\x04"
    if result != expected_result {
        t.Errorf("Pad: Padding does not match expected result")
    }
}
