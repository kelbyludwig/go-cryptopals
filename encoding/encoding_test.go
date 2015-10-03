package encoding

import "testing"

//Test for Set 1 challenge 1
func TestHexToBase64(t *testing.T) {
    input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected_output := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    output := HexToBase64(input)
    if output != expected_output {
        t.Errorf("HexToBase64: Expected output does not match actual output.")
    } else {
        t.Log("HexToBase64: Success!")
    }
}
