package mtrand

const n uint32 = 64
const w uint32 = 32
const m uint32 = 397
const r uint32 = 31
const a uint32 = 0x9908B0DF
const u uint32 = 11
const d uint32 = 0xFFFFFFFF
const s uint32 = 7
const b uint32 = 0x9D2C5680
const t uint32 = 15
const c uint32 = 0xEFC60000
const l uint32 = 18
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
    low_mask := uint32((1 << w) -1)
    for i := uint32(1); i < n-1; i++ {
        mt.MT[i] = low_mask & uint32(f * mt.MT[i-1] ^ (mt.MT[i-1] >> (w-2))) + i
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
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)
    mt.index = mt.index + 1
    return (y & ((1 << w) - 1))
}

func (mt *MTRand) twist() {
	for i := uint32(0); i < n; i++ {
		x := (mt.MT[i] & upper_mask) + (mt.MT[(i+1) % n] & lower_mask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA = xA ^ a
		}
		mt.MT[i] = mt.MT[(i + m) % n] ^ xA
	}
	mt.index = 0
}

func NewMTRand(seed uint32) MTRand {
    mt := MTRand{}
    mt.seed_mt(seed)
    return mt
}
