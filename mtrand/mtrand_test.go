package mtrand

import "testing"
import "fmt"

func TestMTRand(t *testing.T) {
    mtr := NewMTRand(uint32(1))
    fmt.Printf("%x\n",mtr.extract_number())
    fmt.Printf("%x\n",mtr.extract_number())
    fmt.Printf("%x\n",mtr.extract_number())
    fmt.Printf("%x\n",mtr.extract_number())
}
