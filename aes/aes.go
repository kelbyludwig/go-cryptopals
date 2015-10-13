package aes

import "fmt"
import "os"
import "errors"
import "encoding/binary"
import "binary"
import "crypto/rand"
import "crypto/aes"
import "github.com/kelbyludwig/cryptopals/xor"

//TODO: Currently assumes plaintext that is a multiple of the blocksize
func CTREncrypt(key, plaintext []byte) (ciphertext []byte) {
    ctr := uint64(0)
    nonce := uint64(0)
    for len(plaintext) > 0 {
        ctr_block := new(bytes.Buffer)
        binary.Write(ctr_block, binary.LittleEndian, nonce)
        binary.Write(ctr_block, binary.LittleEndian, ctr)
        ctr++
        pt_block := plaintext[:16]
        ct_block := ECBEncrypt(key, ctr_block.Bytes())
        ciphertext = append(ciphertext, ct_block...)
        plaintext = plaintext[16:]
    }
    return ciphertext
}

func CTRDecrypt(key, ciphertext []byte) (plaintext []byte) {
    plaintext = CTREncrypt(key, ciphertext)
    return
}


func CBCEncrypt(key, iv, plaintext []byte) (ciphertext []byte) {
    for len(plaintext) > 0 {
        pt_block := plaintext[:16]
        intermediate_block := xor.Xor(iv, pt_block)
        ct_block := ECBEncrypt(key, intermediate_block)
        ciphertext = append(ciphertext, ct_block...)
        iv = ct_block
        plaintext = plaintext[16:]
    }
    return ciphertext
}

func CBCDecrypt(key, iv, ciphertext []byte) (plaintext []byte) {
    for len(ciphertext) > 0 {
        ct_block := ciphertext[:16]
        pt_block := ECBDecrypt(key, ct_block)
        pt_block = xor.Xor(iv, pt_block)
        plaintext = append(plaintext, pt_block...)
        iv = ct_block
        ciphertext = ciphertext[16:]
    }
    return plaintext
}


func ECBEncrypt(key, plaintext []byte) (ciphertext []byte) {
	block,err := aes.NewCipher(key)

	if err != nil {
		fmt.Println("ECBEncrypt: Error creating block.")
		os.Exit(1)
	}

	// s/o to agl: https://code.google.com/p/go/issues/detail?id=5597
	bs := block.BlockSize()
	if len(plaintext) % bs != 0 {
	    fmt.Println("ECBEncrypt: Need a multiple of the blocksize.")
		os.Exit(1)
	}

	for len(plaintext) > 0 {
        encblock := make([]byte, bs)
		block.Encrypt(encblock, plaintext)
        ciphertext = append(ciphertext, encblock...)
		plaintext = plaintext[bs:]
	}
	return ciphertext
}

func ECBDecrypt(key, ciphertext []byte) (plaintext []byte) {
	block,err := aes.NewCipher(key)

	if err != nil {
		fmt.Println("ECBDecrypt: Error creating block.")
		os.Exit(1)
	}

	// s/o to agl: https://code.google.com/p/go/issues/detail?id=5597
	bs := block.BlockSize()
	if len(ciphertext) % bs != 0 {
	    fmt.Println("ECBDecrypt: Need a multiple of the blocksize.")
		os.Exit(1)
	}

	for len(ciphertext) > 0 {
		decblock := make([]byte, bs)
		block.Decrypt(decblock, ciphertext)
		plaintext = append(plaintext, decblock...)
		ciphertext = ciphertext[bs:]
	}
	return plaintext
}

func Pad(input []byte, block_size int) []byte {
    l := len(input)
    pad_value := block_size - (l % block_size)
    var padding []byte = make([]byte, pad_value)
    for i := 0; i < pad_value; i++ {
        padding[i] = byte(pad_value)
    }
    return append(input, padding...)
}

func StripPad(input []byte) (e error, result []byte) {
    lb := input[len(input)-1]
    lbi := int(lb)
    if lbi == 0 {
        e = errors.New("Invalid Padding")
        result = nil
        return
    }
    result = input
    for i := lbi; i > 0; i-- {
        if result[len(result)-1] != lb {
            e = errors.New("Invalid Padding")
            result = nil
            return
        }
        result = result[:len(result)-1]
    }
    e = nil
    return
}

func RandBytes(size int) []byte {
    bytes := make([]byte, size)
    _, err := rand.Read(bytes)
    if err != nil {
        panic(err)
    }
    return bytes
}

func Blocks(block_size int, input []byte) [][]byte {
    if len(input) % block_size != 0 {
       panic(errors.New("Must break down input that is a multiple of the block size!")) 
    }

    blocks := make([][]byte, int(len(input)/block_size))
    var index int
    for len(input) > 0 {
        blocks[index] = input[:block_size]
        index++
        input = input[block_size:]
    }
    return blocks
}

//CBC Padding Oracle Attack function. Takes an oracle function and a ciphertext to manipualate
func CBCPaddingOracle(oracle func (input []byte) bool, ciphertext []byte) {
    //["AAAAAAAAAAAAAAAA", "AAAAAAAAAAAA\x04\x04\x04\x04"] 
    //PT[n] = \x01
    //CT[n-1] xor PT[n] = IS[n]
    //CT[n-1] xor IS[n] = PT[n]

    //Assuming AES256
    bs := 16
    blocks := Blocks(bs, ciphertext)

    //Panic for empty input ciphertext
    if len(blocks) < 2 {
        panic(errors.New("PANIC!!!! Your ciphertext input is too small"))
    }

    fmt.Println("DEBUG: Number of blocks:", len(blocks))

    //Iterating over blocks
    plaintext := make([]byte, 0)
    for i := 0; i < len(blocks)-1; i++ {
        //Ciphertext block to modify to find valid padding
        mod_block := make([]byte, bs)
        copy(mod_block, blocks[i])
        expected_padding := byte(1)
        intermediate_state := make([]byte, bs)
        //Loop that builds the intermediate state block
        for j := len(mod_block)-1; j >= 0; j-- {
            var iterator_byte byte
            //Loop that determines the appropriate intermediate state byte at each point in the block
            skip_byte := mod_block[j]
            for {
                if iterator_byte == skip_byte {
                    iterator_byte++
                    continue
                }
                mod_block[j] = iterator_byte
                two_blocks := append(mod_block, blocks[i+1]...)
                if oracle(two_blocks) {
                    intermediate_state[j] = iterator_byte ^ expected_padding
                    expected_padding++
                    for k := len(mod_block)-1; k >= j; k-- {
                        mod_block[k] = expected_padding ^ intermediate_state[k]
                    }
                    iterator_byte = 0
                    break
                }
                iterator_byte++
                //We have looped through all bytes
                if iterator_byte == 0 {
                    break
                }
                //We have tried all expected padding values
                if expected_padding == 17 {
                    break
                }
            }
        }
        fmt.Println("IS:")
        fmt.Println(intermediate_state)
        fmt.Println()
        plaintext = append(plaintext, xor.Xor(blocks[i], intermediate_state)...)
    }
    fmt.Println("PLAINTEXT:")
    fmt.Println(plaintext)
    fmt.Println(string(plaintext))
}

