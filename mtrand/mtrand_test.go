package mtrand

import (
	"math/rand"
	"testing"
	"time"
)

func TestMTRand(t *testing.T) {
	mtr := NewMTRand(uint32(1))
	for i := 0; i < 60000; i++ {
		mtr.extract_number()
	}
}

//A test for challenge 22
func TestSeedCrack(t *testing.T) {
	rand_sleep := time.Duration(rand.Intn(50))
	time.Sleep(rand_sleep * 100 * time.Millisecond)
	seed := uint32(time.Now().Unix())
	mtr := NewMTRand(seed)
	num := mtr.extract_number()
	rand_sleep = time.Duration(rand.Intn(50))
	time.Sleep(rand_sleep * 100 * time.Millisecond)
	result := CrackTimeSeed(num)
	if result != seed {
		t.Errorf("SeedCrack: Actual result did not match expected result")
	}
}

//A test for challenge 23
func TestUntemper(t *testing.T) {
	seed := uint32(time.Now().Unix())
	mtr := NewMTRand(seed)
	var arr [624]uint32
	for i := 0; i < 624; i++ {
		arr[i] = mtr.extract_number()
	}
	for i, x := range arr {
		arr[i] = Untemper(x)
	}
	if arr != mtr.MT {
		t.Errorf("Untemper: Actual result did not match exptected result")
	}
}
