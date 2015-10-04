package cryptanalysis

import "os"
import "bufio"
import "testing"
import "github.com/kelbyludwig/cryptopals/encoding"

//Test for Set 1 challenge 3
func TestPlaintextScore(t *testing.T) {
    plaintext := "Cooking MC's like a pound of bacon"
    ciphertext := encoding.HexToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    maxPT,_ := BreakSingleCharXor(ciphertext)
    if string(maxPT) != plaintext {
        t.Errorf("PlaintextScore: Expected output does not match actual output.")
        t.Errorf("Expected: %v\n", plaintext)
        t.Errorf("Actual: %v\n", string(maxPT))
    }

}

//Test for Set 1 challenge 4
func TestSingleByteXorScore(t *testing.T) {
    expected_plaintext := "Now that the party is jumping\n"

    file, err := os.Open("../files/4.txt")
    if err != nil {
        t.Errorf("SingleByteXorScore: Error opening 4.txt")
    }

    defer file.Close()

    scanner := bufio.NewScanner(file)

    var winner []byte
    for scanner.Scan() {
        line := encoding.HexToBytes(scanner.Text())
        if SingleByteXorScore(line) {
            //t.Log("Detected Single Byte XOR: ", line)
            winner = line
            continue
        }
        if SingleByteXorScore(line) && winner != nil {
            t.Errorf("SingleByteXorScore: Detected more than one possible single character xor ciphertext")
        }
    }
    if actual_plaintext,_ := BreakSingleCharXor(winner); string(actual_plaintext) != expected_plaintext {
        t.Errorf("SingleByteXorScore: Expected decrypted text does not match actual decrypted text.")
        t.Errorf("Expected: %v\n", expected_plaintext)
        t.Errorf("Actual:   %v\n", actual_plaintext)
    }

}

func TestHammingWeight(t *testing.T) {
    s1 := []byte("this is a test")
    s2 := []byte("wokka wokka!!!")
    if weight := HammingWeight(s1, s2); weight != 37 {
        t.Errorf("HammingWeight: Expected weight does not match actual weight.")
        t.Errorf("Expected: %d\n",37)
        t.Errorf("Actual:   %d\n", weight)
    }
}

//Test for Set 1 challenge 6
func TestBreakRepeatingKeyXor(t *testing.T) {
    file,err := os.Open("../files/6.txt")
    if err != nil {
        t.Errorf("RepeatKeyXorKeysize: Error opening file.")
    }

    defer file.Close()

    scanner := bufio.NewScanner(file)

    var bytes []byte
    for scanner.Scan() {
        line := scanner.Text()
        bytes = append(bytes, encoding.Base64ToBytes(line)...)
    }

    if FindRepeatKeyXorKeysize(bytes) != 29 {
        t.Errorf("BreakRepeatingKeyXor: Actual key size did not match expected key size.")
    }

    _,key := BreakRepeatingKeyXor(bytes)
    //t.Log(string(key))
    if string(key) != "Terminator X: Bring the noise" {
        t.Errorf("BreakRepeatingKeyXor: Actual result did not match exptected result.")
    }
}
