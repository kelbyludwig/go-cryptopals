package cryptanalysis

import "os"
import "bufio"
import "testing"
import "crypto/rand"
import "encoding/binary"
import "github.com/kelbyludwig/cryptopals/aes"
import "github.com/kelbyludwig/cryptopals/encoding"

//Test for Set 1 challenge 3
func TestPlaintextScore(t *testing.T) {
	plaintext := "Cooking MC's like a pound of bacon"
	ciphertext := encoding.HexToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	maxPT, _ := BreakSingleCharXor(ciphertext)
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
	if actual_plaintext, _ := BreakSingleCharXor(winner); string(actual_plaintext) != expected_plaintext {
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
		t.Errorf("Expected: %d\n", 37)
		t.Errorf("Actual:   %d\n", weight)
	}
}

//Test for Set 1 challenge 6
func TestBreakRepeatingKeyXor(t *testing.T) {
	file, err := os.Open("../files/6.txt")
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

	_, key := BreakRepeatingKeyXor(bytes)
	//t.Log(string(key))
	if string(key) != "Terminator X: Bring the noise" {
		t.Errorf("BreakRepeatingKeyXor: Actual result did not match exptected result.")
	}
}

//Test for Set 1 challenge 8
func TestDetectECBMode(t *testing.T) {
	file, err := os.Open("../files/8.txt")
	if err != nil {
		t.Errorf("DetectECBMode: Error opening file.")
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	var detected bool
	for scanner.Scan() {
		line := encoding.HexToBytes(scanner.Text())
		if DetectECB256Mode(line) && detected {
			t.Errorf("DetectECBMode: Detected multiple lines.")
			detected = true
		}
	}

}

//Test case for Set 2 Challenge 11
func TestDetectionOracle(t *testing.T) {
	//Simulating data i would send myself
	testcase := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	//Big ugly oracle function.
	oracle := func(plaintext []byte) (result []byte, mode string) {
		key := make([]byte, 16)
		_, err := rand.Read(key)
		if err != nil {
			t.Errorf("DetectionOracle: Reading random bytes failed.")
		}

		//"Coin flip"
		var number byte
		binary.Read(rand.Reader, binary.LittleEndian, &number)
		cbc := false
		if number%2 == 0 {
			cbc = true
		}

		//Random prefix and postfix
		var pre uint32
		var post uint32
		binary.Read(rand.Reader, binary.LittleEndian, &pre)
		binary.Read(rand.Reader, binary.LittleEndian, &post)
		predata := make([]byte, pre%10)
		postdata := make([]byte, post%10)
		rand.Read(predata)
		rand.Read(postdata)
		data := append(predata, plaintext...)
		data = append(data, postdata...)
		data = aes.Pad(data, 16)

		if cbc {
			iv := make([]byte, 16)
			_, err := rand.Read(iv)
			if err != nil {
				t.Errorf("DetectionOracle: Reading random bytes failed.")
			}
			result = aes.CBCEncrypt(key, iv, data)
			mode = "CBC"
			return
		} else {
			result = aes.ECBEncrypt(key, data)
			mode = "ECB"
			return
		}
	}

	//Iterate oracle
	for i := 0; i < 40; i++ {
		data, mode := oracle(testcase)
		if output := AESModeDetectionOracle(data); output != mode {
			t.Errorf("DetectionOracle: Detection oracle failed to guess correctly.")
			t.Errorf("\tExpected: %v", mode)
			t.Errorf("\tGuessed:  %v", output)
		}
	}
}

//Oracle for set 2 challenge 12
func ECBChosenPrefix(input []byte, key []byte) []byte {
	secret := encoding.Base64ToBytes(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`)
	data := append(input, secret...)
	data = aes.Pad(data, 16)
	return aes.ECBEncrypt(key, data)

}

//Oracle for set 2 challenge 14
func ECBChosenInfix(random_prefix, input, key []byte) []byte {
	secret := encoding.Base64ToBytes(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`)
	data := append(random_prefix, input...)
	data = append(data, secret...)
	data = aes.Pad(data, 16)
	return aes.ECBEncrypt(key, data)

}

//Test for set 2 challenge 12
func TestECBChosenPrefixAttack(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		t.Errorf("ECBChosenPrefixAttack: Failed reading from urandom")
	}

	oracle := func(input []byte) []byte { return ECBChosenPrefix(input, key) }

	//Determine block size of oracle
	bs := DetermineOracleBlockSize(oracle)
	if bs != 16 {
		t.Errorf("ECBChosenPrefixAttack: Failed to determine correct block size")
	}

	//Determine if oracle is using ECB mode

	//TODO: This is silly. You should make your cryptanalysis functions take an oracle function. Will be more reusable.
	data := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if !DetectECB256Mode(oracle(data)) {
		t.Errorf("ECBChosenPrefixAttack: Failed to correctly guess that the oracle used ECB mode.")
	}

	result := ECBSecretSuffixAttack(oracle)
	expected_result := `Rollin' in my 5.0
    With my rag-top down so my hair can blow
    The girlies on standby waving just to say hi
    Did you stop? No, I just drove by`
	if result[:12] != expected_result[:12] {
		t.Errorf("ECBChosenPrefixAttack: Expected decryption did not actually match real decryption")
	}

}

//Test for set 2 challenge 14
func TestECBChosenInfixAttack(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		t.Errorf("ECBChosenInfixAttack: Failed reading from urandom")
	}
	var prefix uint32
	binary.Read(rand.Reader, binary.LittleEndian, &prefix)
	num := int(prefix % 32)
	random_prefix := aes.RandBytes(num)
	oracle := func(input []byte) []byte { return ECBChosenInfix(random_prefix, input, key) }

	//Determine block size of oracle
	bs := DetermineOracleBlockSize(oracle)
	if bs != 16 {
		t.Errorf("ECBChosenInfixAttack: Failed to determine correct block size")
	}

	//Determine if oracle is using ECB mode

	//TODO: This is silly. You should make your cryptanalysis functions take an oracle function. Will be more reusable.
	data := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if !DetectECB256Mode(oracle(data)) {
		t.Errorf("ECBChosenInfixAttack: Failed to correctly guess that the oracle used ECB mode.")
	}

	result := ECBSecretInfixAttack(oracle)
	expected_result := `Rollin' in my 5.0
    With my rag-top down so my hair can blow
    The girlies on standby waving just to say hi
    Did you stop? No, I just drove by`
	if result[:12] != expected_result[:12] {
		t.Errorf("ECBChosenInfixAttack: Expected decryption did not actually match real decryption")
	}

}

//Test for set 3 challenge 20
func TestRepeatNonceCTRMode(t *testing.T) {
	file, err := os.Open("../files/20.txt")
	if err != nil {
		t.Errorf("DetectECBMode: Error opening file.")
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	smallest_len := 99999999
	var lines [][]byte
	for scanner.Scan() {
		line := encoding.Base64ToBytes(scanner.Text())
		if len(line) < smallest_len {
			smallest_len = len(line)
		}
		lines = append(lines, line)
	}

	var ciphertext_blob []byte
	for _, l := range lines {
		ciphertext_blob = append(ciphertext_blob, l[:smallest_len]...)
	}
	pt, _ := BreakRepeatingKeyXor(ciphertext_blob)
	expected_result := "I'm rated \"R\"...this is a warning, ya better void"
	if string(pt[:len(expected_result)]) != expected_result {
		t.Errorf("RepeatNonceCTRMode: Expected result did not match actual result!")
	}

}

//Test for challenge 25
func TestCTREdit(t *testing.T) {
	plaintext := []byte("My shell, mechanical found ghost. But my ghetto is animal found toast")
	key := aes.RandBytes(16)
	nonce := uint64(0)
	ciphertext := aes.CTREncrypt(key, nonce, plaintext)
	oracle := func(ct []byte, offset int, insert []byte) []byte {
		pt := aes.CTRDecrypt(key, nonce, ct)
		begin := pt[0:offset]
		end := pt[offset+len(insert):]
		newPt := append(begin, insert...)
		newPt = append(newPt, end...)
		return aes.CTREncrypt(key, nonce, newPt)
	}
	recoveredPlaintext := CTREditAttack(ciphertext, oracle)
	if string(recoveredPlaintext) != string(plaintext) {
		t.Errorf("CTREdit: Attack failed.")
	}
}
