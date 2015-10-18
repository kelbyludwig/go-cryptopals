package mtrand

const n uint32 = 624
const w uint32 = 32
const m uint32 = 397
const r uint32 = 31
const a uint32 = 0x9908B0DF
const d uint32 = 0xFFFFFFFF
const c uint32 = 0xEFC60000
const f uint32 = 1812433253
const lower_mask uint32 = (1 << r) - 1
const upper_mask uint32 = (^lower_mask) & ((1 << w)-1)

type MTRand struct {
    MT [n]uint32
    index uint32
}

func (mt *MTRand) seed_mt(seed uint32) {
    mt.index = n
    mt.MT[0] = seed
    for i := uint32(1); i < n; i++ {
        mt.MT[i] = uint32(1812433253 * (mt.MT[i - 1] ^ mt.MT[i - 1] >> 30) + i)
    }
}

func (mt *MTRand) extract_number() uint32 {
    if mt.index >= n {
        if mt.index > n {
            panic("Generator was never seeded you dork!!")
        }
        mt.twist()
    }
    var y uint32 = mt.MT[mt.index]
    y ^= uint32(y >> 11)
    y ^= uint32((y << 7) & 2636928640)
    y ^= uint32((y << 15) & 4022730752)
    y ^= uint32(y >> 18)
    mt.index = mt.index + 1
    return y
}

func (mt *MTRand) twist() {
	for i := uint32(0); i < n; i++ {
        y := uint32((mt.MT[i] & 0x80000000) + (mt.MT[(i + 1) % 624] & 0x7fffffff))
        mt.MT[i] = mt.MT[(i + 397) % 624] ^ y >> 1
        if y % 2 != 0 {
            mt.MT[i] = mt.MT[i] ^ 0x9908b0df
        }
	}
	mt.index = 0
}

func NewMTRand(seed uint32) MTRand {
    mt := MTRand{}
    mt.seed_mt(seed)
    return mt
}
