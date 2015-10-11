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


func BreakSingleCharXor(ciphertext []byte) (plaintext []byte, key byte) {
    bytes := xor.AllBytes()
    var maxScore float64 = 0.0

    for _,b := range bytes {
        var potential_plaintext []byte = make([]byte, len(ciphertext))
        for i,c := range ciphertext {
            potential_plaintext[i] = c ^ b
        }
        score := PlaintextScore(potential_plaintext)
        if score > maxScore {
            maxScore = score
            plaintext = potential_plaintext
            key = b
        }
    }
    return
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

func FindRepeatKeyXorKeysize(ciphertext []byte) int {
    minWeight := 4.0
    keySize := 0
    for i := 4; i < 40; i++ {
        if (4*i) > len(ciphertext) {
            return keySize
        }
        slice1 := ciphertext[0:i]
        slice2 := ciphertext[i:(2*i)]
        slice3 := ciphertext[(2*i):(3*i)]
        slice4 := ciphertext[(3*i):(4*i)]

        weight1 := float64(HammingWeight(slice1, slice2)) / float64(i)
        weight2 := float64(HammingWeight(slice3, slice4)) / float64(i)
        weight3 := float64(HammingWeight(slice1, slice3)) / float64(i)
        weight4 := float64(HammingWeight(slice2, slice4)) / float64(i)
        weight := (weight1 + weight2 + weight3 + weight4) / 4.0

        if weight < minWeight {
            minWeight = weight
            keySize = i
        }
    }
    return keySize
}

func BreakRepeatingKeyXor(ciphertext []byte) (plaintext, key []byte) {
    //Determine keysize.
    keysize := FindRepeatKeyXorKeysize(ciphertext)

    //break ciphertext into blocks
    numblocks := len(ciphertext)/keysize
    var blocks [][]byte = make([][]byte, numblocks)
    for i := 0; i < len(ciphertext)-keysize; i += keysize {
        blocks[i/keysize] = ciphertext[i:i+keysize]
    }

    //initialize inner slices
    var transposed [][]byte = make([][]byte, keysize)
    for i,_ := range transposed {
        transposed[i] = make([]byte, numblocks)
    }

    //transpose blocks
    for i,block := range blocks {
        for j,_ := range block {
            transposed[j][i] = blocks[i][j]
        }
    }

    //Iterate over tranposed blocks cracking each key at a time.
    for _,block := range transposed {
        _,keybyte := BreakSingleCharXor(block)
        key = append(key, keybyte)
    }
    return xor.RepeatingKeyXor(key, ciphertext), key
}

//If there are duplicate ciphertext blocks, return true.
func DetectECB256Mode(ciphertext []byte) bool {
    var blocks []string = make([]string, len(ciphertext)/16)
    var index int
    for len(ciphertext) > 0 {
        blocks[index] = string(ciphertext[:16])
        ciphertext = ciphertext[16:]
        index++
    }
    var dups map[string]int = make(map[string]int)
    for _,block := range blocks {
        _,exists := dups[block]
        if exists {
            return true
        } else {
            dups[block] = 0
        }
    }
    return false
}

func DetectECB192Mode(ciphertext []byte) bool {
    var blocks []string = make([]string, len(ciphertext)/12)
    var index int
    for len(ciphertext) > 0 {
        blocks[index] = string(ciphertext[:12])
        ciphertext = ciphertext[12:]
        index++
    }
    var dups map[string]int = make(map[string]int)
    for _,block := range blocks {
        _,exists := dups[block]
        if exists {
            return true
        } else {
            dups[block] = 0
        }
    }
    return false
}

func DetectECB128Mode(ciphertext []byte) bool {
    var blocks []string = make([]string, len(ciphertext)/8)
    var index int
    for len(ciphertext) > 0 {
        blocks[index] = string(ciphertext[:8])
        ciphertext = ciphertext[8:]
        index++
    }
    var dups map[string]int = make(map[string]int)
    for _,block := range blocks {
        _,exists := dups[block]
        if exists {
            return true
        } else {
            dups[block] = 0
        }
    }
    return false
}


func AESModeDetectionOracle(ciphertext []byte) string {
    if DetectECB256Mode(ciphertext) {
        return "ECB"
    } else {
        return "CBC"
    }
}

//Takes an oracle function (should be a block cipher) and returns the block size.
func DetermineOracleBlockSize(oracle func(input []byte) []byte) int {
    data := []byte("")
    original_len := len(oracle(data))
    for  {
        data = append(data, byte('A'))
        new_len := len(oracle(data))
        if new_len > original_len {
            return new_len - original_len
        }
    }
}

func ECBSecretSuffixAttack(oracle func(input []byte) []byte) string {
    bs := DetermineOracleBlockSize(oracle)
    //Change this if necessary
    secret_len := bs * 10
    as := func(x int) []byte {
        block := make([]byte, x)
        for i := 0; i < x; i++ {
            block[i] = byte('A')
        }
        return block
    }
    block := as(secret_len-1)
    block_with_pt := oracle(block)[:secret_len]

    var result []byte
    for len(result) < secret_len-1 {
        var b byte
        for b = 0; b < 255; b++ {
            ctblock := oracle(append(block, b))[:secret_len]
            if string(ctblock) == string(block_with_pt) {
                result = append(result, b)
                new_as := as(secret_len-len(result)-1)
                block_with_pt = oracle(new_as)[:secret_len]
                block = append(new_as, result...)
                break
            }
            if b == 254 {
                return string(result)
            }
        }
    }
    return string(result)
}

func DetermineDrop(oracle func(input []byte) []byte) int {
    var as []byte
    for !DetectECB256Mode(oracle(as)) {
        as = append(as, 'A')
    }
    ct := oracle(as)
    var i int
    for {
        prev_block := ct[:16]
        next_block := ct[16:32]
        if string(prev_block) == string(next_block) {
           break
        }
        i += 1
        ct = ct[16:]
    }
    return 32 - (len(as) - (i*16))
}

func ECBSecretInfixAttack(oracle func(input []byte) []byte) string {
    bs := DetermineOracleBlockSize(oracle)
    secret_size := DetermineDrop(oracle)
    offset := bs - (secret_size % bs)
    drop_size := offset + secret_size
    new_oracle := func (input []byte) []byte {
        pre := make([]byte, offset)
        input = append(pre, input...)
        return oracle(input)[drop_size:]
    }

    secret_len := (bs * 10)

    as := func(x int) []byte {
        block := make([]byte, x)
        for i := 0; i < x; i++ {
            block[i] = byte('A')
        }
        return block
    }
    block := as(secret_len-1)
    block_with_pt := new_oracle(block)[:secret_len]

    var result []byte
    for len(result) < secret_len-1 {
        var b byte
        for b = 0; b < 255; b++ {
            ctblock := new_oracle(append(block, b))[:secret_len]
            if string(ctblock) == string(block_with_pt) {
                result = append(result, b)
                new_as := as(secret_len-len(result)-1)
                block_with_pt = new_oracle(new_as)[:secret_len]
                block = append(new_as, result...)
                break
            }
            if b == 254 {
                return string(result)
            }
        }
    }
    return string(result)


}
