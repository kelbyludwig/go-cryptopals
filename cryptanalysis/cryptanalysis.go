package cryptanalysis

import "github.com/kelbyludwig/cryptopals/xor"

//Scores a bytestring by the number of bytes that correspond to printable characters
func PlaintextScore(bytestring []byte) float64 {
    var weight float64 = 0.0
    for _,b := range bytestring {

        //The byte is a capital letter
        if b >= 0x41 && b <= 0x5a {
            weight += 1.0
            continue
        }
        //The byte is a lowercase letter
        if b >= 0x61 && b <= 0x7a {
            weight += 1.0
            continue
        }

        //The byte is a space
        if b == 0x20 {
            weight += 1.0
            continue
        }

        //The byte is punctutation
        if (b >= 0x20 && b <= 0x2f) ||
           (b >= 0x3a && b <= 0x40) ||
           (b >= 0x5b && b <= 0x60) ||
           (b >= 0x7b && b <= 0x7e) {
            continue
        }

        //The byte is a number
        if (b >= 0x30 && b <= 0x39) {
            weight += .1
            continue
        }

    }

    //Return normalized score.
    return (weight / float64(len(bytestring)))
}

//Attempts to detect if a ciphertext was encrypted using single character xor
func SingleByteXorScore(bytestring []byte) bool {
    var maxScore float64
    bytes := xor.AllBytes()
    for _,b := range bytes {
        pt := xor.SingleCharXor(b, bytestring)
        if score := PlaintextScore(pt); score > maxScore {
            maxScore = score
        }
    }

    //This value is optimized for challenge 4. Can be changed if necessary
    if maxScore >= .90 {
        return true
    } else {
        return false
    }
}


func FindSingleCharXorPT(ciphertext []byte) []byte {
    bytes := xor.AllBytes()
    var maxScore float64 = 0.0
    var maxPT []byte

    for _,b := range bytes {
        var potential_plaintext []byte = make([]byte, len(ciphertext))
        for i,c := range ciphertext {
            potential_plaintext[i] = c ^ b
        }
        score := PlaintextScore(potential_plaintext)
        if score > maxScore {
            maxScore = score
            maxPT = potential_plaintext
        }
    }
    return maxPT
}

func HammingWeight(bs1 []byte, bs2[]byte) int {
    var weight int
    bs := xor.Xor(bs1, bs2)
    for _,b := range bs {
        var i byte
        for i = 1; i < 128; i= i<<1 {
            if b & i == i {
                weight += 1
            }
        }
    }
    return weight
}
