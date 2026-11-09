package banglaqr

// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no xorout.
var crcTab = func() (t [256]uint16) {
	for i := range t {
		c := uint16(i) << 8
		for j := 0; j < 8; j++ {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return
}()

func crc16(s string) uint16 {
	c := uint16(0xFFFF)
	for i := 0; i < len(s); i++ {
		c = c<<8 ^ crcTab[byte(c>>8)^s[i]]
	}
	return c
}

func crc16b(b []byte) uint16 {
	c := uint16(0xFFFF)
	for _, x := range b {
		c = c<<8 ^ crcTab[byte(c>>8)^x]
	}
	return c
}

const hexUpper = "0123456789ABCDEF"

func appendHex4(b []byte, v uint16) []byte {
	return append(b, hexUpper[v>>12], hexUpper[v>>8&15], hexUpper[v>>4&15], hexUpper[v&15])
}

func parseHex4(s string) (uint16, bool) {
	if len(s) != 4 {
		return 0, false
	}
	var v uint16
	for i := 0; i < 4; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		default:
			return 0, false
		}
		v = v<<4 | uint16(c)
	}
	return v, true
}
