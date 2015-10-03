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
