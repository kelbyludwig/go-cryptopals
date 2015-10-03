package xor

import "github.com/kelbyludwig/cryptopals/encoding"
import "testing"

//Test for Set 1 challenge 2
func TestXor(t *testing.T) {
    text1 := encoding.HexToBytes("1c0111001f010100061a024b53535009181c")
    text2 := encoding.HexToBytes("686974207468652062756c6c277320657965")

    expected_output := "746865206b696420646f6e277420706c6179"
    output := encoding.BytesToHex(Xor(text1,text2))
    if output != expected_output {
        t.Errorf("Xor: Expected output does not match actual output.")
    }
}

func TestRepeatKeyXor(t *testing.T) {
    plaintext := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
    key := []byte("ICE")
    ciphertext := encoding.BytesToHex(RepeatKeyXor(key, plaintext))
    expected_ciphertext := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    if ciphertext != expected_ciphertext {
        t.Errorf("RepeatKeyXor: Expected output does not match actual output.")
    }
}
