package mtrand

import "testing"
import "math/rand"
import "time"

func TestMTRand(t *testing.T) {
    mtr := NewMTRand(uint32(1))
    for i := 0; i < 60000; i++{
        mtr.extract_number()
    }
}

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
