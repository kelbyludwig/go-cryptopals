package mtrand

import "testing"

func TestMTRand(t *testing.T) {
    mtr := NewMTRand(uint32(1))
    for i := 0; i < 60000; i++{
        mtr.extract_number()
    }
}
