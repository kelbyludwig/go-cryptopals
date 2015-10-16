package aes

import "github.com/kelbyludwig/cryptopals/encoding"
import "math/rand"
import "time"
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

//Test for Set 2 challenge 9
func TestPad(t *testing.T) {
    input := []byte("YELLOW SUBMARINE")
    result := string(Pad(input, 20))
    expected_result := "YELLOW SUBMARINE\x04\x04\x04\x04"
    if result != expected_result {
        t.Errorf("Pad: Padding does not match expected result")
    }
}

//Test for Set 2 challenge 10
func TestCBCMode(t *testing.T) {
    key := []byte("YELLOW SUBMARINE")
    iv := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    file,err := os.Open("../files/10.txt")
    if err != nil {
        fmt.Println("[ERR] CBCMode test failed to open file.")
        os.Exit(1)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)

    var ciphertext []byte
    for scanner.Scan() {
        line := encoding.Base64ToBytes(scanner.Text())
        ciphertext = append(ciphertext, []byte(line)...)
    }

    if string(CBCEncrypt(key, iv, (CBCDecrypt(key, iv, ciphertext)))) != string(ciphertext) {
        t.Errorf("CBCMode: Expected result did not match actual result")
    }
}

func TestPaddingValidation(t *testing.T) {
    t1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
    e1,r1 := StripPad(t1)
    if e1 != nil {
        t.Errorf("PaddingValidaton: Padding validation returned error when it shouldnt have")
    }
    if string(r1) != "ICE ICE BABY" {
        t.Errorf("PaddingValidation: Padding strip is invalid")
        t.Log(string(r1))
    }
    t2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
    e2,_ := StripPad(t2)
    if e2 == nil {
        t.Errorf("PaddingValidation: Invalid padding was considered valid")
    }
    t3 := []byte("ICE ICE BABY\x01\x02\x03\x04")
    e3,_ := StripPad(t3)
    if e3 == nil {
        t.Errorf("PaddingValidation: Invalid padding was considered valid")
    }
    t4 := []byte("ICE ICE BABY\x04\x04\x04")
    e4,_ := StripPad(t4)
    if e4 == nil {
        t.Errorf("PaddingValidation: Invalid padding was considered valid")
    }

    key := RandBytes(16)
    iv := RandBytes(16)
    ct1 := CBCEncrypt(key, iv, t1)
    ct2 := CBCEncrypt(key, iv, t2)
    if !CBCCookieValidate(key, iv, ct1) {
       t.Errorf("PaddingValidation: Cookie validation function failed!")
    }
    if CBCCookieValidate(key, iv, ct2) {
       t.Errorf("PaddingValidation: Cookie validation function failed!")
    }
}

//One of the oracle functions for the CBC padding oracle.
func CBCCookieCreate() (key, iv, ct []byte) {
    key = RandBytes(16)
    iv  = RandBytes(16)
    file,_ := os.Open("../files/17.txt")
    defer file.Close()
    scanner := bufio.NewScanner(file)
    r := rand.NewSource(time.Now().UnixNano())
    rnd := rand.New(r)
    line := rnd.Intn(10)
    var pt []byte
    var i int
    for scanner.Scan() {
        if i == line {
            pt = encoding.Base64ToBytes(scanner.Text())
            break
        }
        i++
        scanner.Text()
    }
    pt = Pad(pt, 16)
    fmt.Println("PLAINTEXT:\n", "(", len(pt), ")", string(pt), "\n", pt)
    ct = CBCEncrypt(key, iv, pt)
    return
}

//The CBC padding oracle function
func CBCCookieValidate(key, iv, ciphertext []byte) bool {
    pt := CBCDecrypt(key, iv, ciphertext)
    //fmt.Println("------------------")
    //fmt.Println("DEBUG: Decrypted\n", pt)
    e1,_ := StripPad(pt)
    if e1 != nil {
        return false
    } else {
        return true
    }
}
//TODO: This is not working 100%. Last block is scrambled...
func TestCBCPaddingOracle(t *testing.T) {
    key, iv, ct := CBCCookieCreate()
    oracle := func (in []byte) bool { return CBCCookieValidate(key, iv, in) }
    CBCPaddingOracle(oracle, ct)
}

//Test for set 3 challenge 18
func TestCTRDecrypt(t *testing.T) {
    ct := encoding.Base64ToBytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key := []byte("YELLOW SUBMARINE")
    result := string(CTRDecrypt(key, uint64(0), ct))
    if result != "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby " {
        t.Errorf("CTRDecrypt: Actual result did not match expected result!")
        t.Errorf("%v", []byte(result))
        t.Errorf("%v", []byte("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby"))
    }
}
