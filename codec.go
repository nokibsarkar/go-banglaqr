package banglaqr

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// Binary format v1 (little-endian trailer):
//
//	'B' 'Q' ver(1) flags
//	uvarint srcLen, src bytes (full payload incl. CRC field)
//	uvarint nRoot, nRoot × { tag u8, uvarint off, len u8 }
//	uvarint nSub,  nSub  × { tag u8, uvarint off, len u8 }   (tag-62 children)
//	crc32c u32 over everything above
//
// flags: bit0 dynamic(01=12), bit1 has tag 54, bit2 has tag 62.
var (
	ErrBlob         = errors.New("banglaqr: malformed binary template")
	ErrBlobMagic    = errors.New("banglaqr: not a binary template")
	ErrBlobVersion  = errors.New("banglaqr: unsupported binary template version")
	ErrBlobChecksum = errors.New("banglaqr: binary template checksum mismatch")
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// MarshalBinary serializes the template compactly for storage.
func (t *Template) MarshalBinary() ([]byte, error) {
	if t == nil {
		return nil, ErrBlob
	}
	return t.AppendBinary(make([]byte, 0, len(t.src)+8+4*(len(t.root)+len(t.sub))))
}

// AppendBinary appends the serialized form to dst without extra allocation
// when capacity suffices.
func (t *Template) AppendBinary(dst []byte) ([]byte, error) {
	if t == nil || len(t.src) < 14 || len(t.root) == 0 {
		return dst, ErrBlob
	}
	start := len(dst)
	dst = append(dst, 'B', 'Q', 1, t.flags())
	dst = binary.AppendUvarint(dst, uint64(len(t.src)))
	dst = append(dst, t.src...)
	for _, es := range [2][]elem{t.root, t.sub} {
		dst = binary.AppendUvarint(dst, uint64(len(es)))
		for _, e := range es {
			dst = append(dst, e.tag)
			dst = binary.AppendUvarint(dst, uint64(e.off))
			dst = append(dst, e.n)
		}
	}
	return binary.LittleEndian.AppendUint32(dst, crc32.Checksum(dst[start:], castagnoli)), nil
}

// Decode rebuilds a Template from MarshalBinary output. It copies the source
// once, verifies the CRC-32C trailer and that the stored index tiles the
// payload exactly, and re-checks profile invariants — without rescanning
// values or recomputing the QR CRC (use VerifyCRC for untrusted storage).
func Decode(b []byte) (*Template, error) {
	t := new(Template)
	if err := t.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return t, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler. The receiver is only
// modified on success.
func (t *Template) UnmarshalBinary(b []byte) error {
	if len(b) < 9 {
		return ErrBlob
	}
	if b[0] != 'B' || b[1] != 'Q' {
		return ErrBlobMagic
	}
	if b[2] != 1 {
		return ErrBlobVersion
	}
	body := b[:len(b)-4]
	if crc32.Checksum(body, castagnoli) != binary.LittleEndian.Uint32(b[len(b)-4:]) {
		return ErrBlobChecksum
	}
	flags := b[3]
	p := body[4:]
	srcLen, k := binary.Uvarint(p)
	if k <= 0 || srcLen < 14 || srcLen > maxPayload || uint64(len(p)-k) < srcLen {
		return ErrBlob
	}
	p = p[k:]
	src := string(p[:srcLen])
	p = p[srcLen:]

	var lists [2][]elem
	for li := range lists {
		cnt, k := binary.Uvarint(p)
		if k <= 0 || cnt > 100 {
			return ErrBlob
		}
		p = p[k:]
		es := make([]elem, cnt)
		for i := range es {
			if len(p) < 1 {
				return ErrBlob
			}
			tag := p[0]
			off, k := binary.Uvarint(p[1:])
			if k <= 0 || off > maxPayload || len(p) < 1+k+1 {
				return ErrBlob
			}
			n := p[1+k]
			if tag > 99 || n > 99 {
				return ErrBlob
			}
			es[i] = elem{tag: tag, n: n, off: uint16(off)}
			p = p[1+k+1:]
		}
		lists[li] = es
	}
	if len(p) != 0 {
		return ErrBlob
	}
	n := len(src)
	if src[n-8:n-4] != "6304" {
		return ErrBlob
	}
	if _, ok := parseHex4(src[n-4:]); !ok {
		return ErrBlob
	}
	nt := &Template{src: src, root: lists[0], sub: lists[1]}
	if err := tile(src, nt.root, 0, n-8); err != nil {
		return err
	}
	st, en, has62 := nt.range62()
	if has62 {
		if err := tile(src, nt.sub, st, en); err != nil {
			return err
		}
	} else if len(nt.sub) != 0 {
		return ErrBlob
	}
	if err := nt.finish(false); err != nil {
		return err
	}
	if nt.flags() != flags {
		return ErrBlob
	}
	*t = *nt
	return nil
}

// tile verifies es are contiguous, in order, match their headers in src, are
// unique, and cover exactly src[start:end].
func tile(src string, es []elem, start, end int) error {
	var seen [100]bool
	pos := start
	for _, e := range es {
		if int(e.off) != pos || e.end() > end || seen[e.tag] {
			return ErrBlob
		}
		seen[e.tag] = true
		h := src[pos : pos+4]
		if h[0]-'0' != e.tag/10 || h[1]-'0' != e.tag%10 || h[2]-'0' != e.n/10 || h[3]-'0' != e.n%10 {
			return ErrBlob
		}
		pos = e.end()
	}
	if pos != end {
		return ErrBlob
	}
	return nil
}
