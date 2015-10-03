package cryptanalysis

import "os"
import "bufio"
import "testing"
import "github.com/kelbyludwig/cryptopals/encoding"

//Test for Set 1 challenge 3
func TestPlaintextScore(t *testing.T) {
    plaintext := "Cooking MC's like a pound of bacon"
    ciphertext := encoding.HexToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    maxPT := FindSingleCharXorPT(ciphertext)
    if string(maxPT) != plaintext {
        t.Errorf("PlaintextScore: Expected output does not match actual output.")
        t.Errorf("Expected: %v\n", plaintext)
        t.Errorf("Actual: %v\n", string(maxPT))
    }

}

func TestSingleByteXorScore(t *testing.T) {
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
            t.Log("Detected Single Byte XOR: ", line)
            winner = line
            continue
        }
        if SingleByteXorScore(line) && winner != nil {
            t.Errorf("SingleByteXorScore: Detected more than one possible single character xor ciphertext")
        }
    }
    t.Log("Plaintext: ", string(FindSingleCharXorPT(winner)))

}
