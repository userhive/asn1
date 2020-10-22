package asn1ber

import (
	"bytes"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	// longFormBitmaskLen is the mask to apply to the length byte to see if
	// a long-form byte sequence is used.
	longFormBitmaskLen = 0x80

	// valueBitmaskLen is the mask to apply to the length byte to get the
	// number of bytes in the long-form byte sequence.
	valueBitmaskLen = 0x7f
)

// ReadByte reads a byte from r.
func ReadByte(r io.Reader) (int, byte, error) {
	var buf [1]byte
	n, err := r.Read(buf[:])
	switch {
	case err == io.EOF:
		return n, 0, ErrUnexpectedEOF
	case err != nil:
		return n, 0, err
	}
	return n, buf[0], nil
}

// ParseHeader parses a ber packet header from the reader.
func ParseHeader(r io.Reader) (int, Class, Type, Tag, int, error) {
	n, class, typ, tag, err := ParseIdentifier(r)
	if err != nil {
		return n, 0, 0, 0, 0, err
	}
	nn, count, err := ParseCount(r)
	if err != nil {
		return n + nn, class, typ, tag, count, err
	}
	n += nn
	// Validate length type with identifier (x.600, 8.1.3.2.a)
	switch {
	case count == -1 && typ == TypePrimitive:
		return n, class, typ, tag, 0, ErrIndefiniteLengthUsedWithPrimitiveType
	case count < -1:
		return n, class, typ, tag, 0, ErrLengthCannotBeLessThanNegative1
	}
	return n, class, typ, tag, count, nil
}

// ParseIdentifier parses the ber packet class, tag type, and tag from the
// reader.
func ParseIdentifier(r io.Reader) (int, Class, Type, Tag, error) {
	// identifier byte
	n, b, err := ReadByte(r)
	if err != nil {
		return n, 0, 0, 0, err
	}
	class, typ, tag := Class(b)&ClassPrivate, Type(b)&TypeConstructed, Tag(0)
	if tag := Tag(b) & TagBitmask; tag != tagHigh {
		// short-form tag
		return n, class, typ, tag, nil
	}
	// high-tag-number tag
	count := 0
	for {
		nn, b, err := ReadByte(r)
		if err != nil {
			return n, 0, 0, 0, err
		}
		count += nn
		n += nn
		// Lowest 7 bits get appended to the tag value (x.690, 8.1.2.4.2.b)
		tag <<= 7
		tag |= Tag(b) & tagHighValueBitmask
		// First byte may not be all zeros (x.690, 8.1.2.4.2.c)
		if count == 1 && tag == 0 {
			return n, 0, 0, 0, ErrInvalidHighByte
		}
		// Overflow of int64
		// TODO: support big int tags?
		if count > 9 {
			return n, 0, 0, 0, ErrTagValueOverflow
		}
		// Top bit of 0 means this is the last byte in the high-tag-number tag (x.690, 8.1.2.4.2.a)
		if Tag(b)&tagHighContinueBitmask == 0 {
			break
		}
	}
	return n, class, typ, tag, nil
}

func ParseCount(r io.Reader) (int, int, error) {
	var l int
	// length byte
	n, b, err := ReadByte(r)
	if err != nil {
		return 0, 0, err
	}
	switch {
	case b == 0xFF:
		// Invalid 0xFF (x.600, 8.1.3.5.c)
		return n, 0, ErrInvalidLength
	case b == longFormBitmaskLen:
		// Indefinite form, we have to decode packets until we encounter an EOC packet (x.600, 8.1.3.6)
		l = -1
	case b&longFormBitmaskLen == 0:
		// Short definite form, extract the length from the bottom 7 bits (x.600, 8.1.3.4)
		l = int(b) & valueBitmaskLen
	case b&longFormBitmaskLen != 0:
		// Long definite form, extract the number of length bytes to follow from the bottom 7 bits (x.600, 8.1.3.5.b)
		count := int(b) & valueBitmaskLen
		// Protect against overflow
		// TODO: support big int length?
		if count > 8 {
			return n, 0, ErrLengthValueOverflow
		}
		// Accumulate into a 64-bit variable
		var ll int64
		for i := 0; i < count; i++ {
			_, b, err = ReadByte(r)
			if err != nil {
				return n, 0, err
			}
			n++
			// x.600, 8.1.3.5
			ll <<= 8
			ll |= int64(b)
		}
		// Cast to a platform-specific integer
		l = int(ll)
		// Ensure we didn't overflow
		if int64(l) != ll {
			return n, 0, ErrLengthValueOverflow
		}
	default:
		return n, 0, ErrInvalidLength
	}
	return n, l, nil
}

func ParseReal(buf []byte) (float64, error) {
	if len(buf) == 0 {
		return 0.0, nil
	}
	var f float64
	var err error
	switch {
	case buf[0]&0x80 == 0x80:
		f, err = ParseBinaryFloat(buf)
	case buf[0]&0xC0 == 0x0:
		f, err = ParseDecimalFloat(buf)
	case buf[0]&0xC0 == 0x40:
		f, err = ParseSpecialFloat(buf)
	default:
		return 0.0, ErrInvalidInfoBlock
	}
	if err != nil {
		return 0.0, err
	}
	if f == 0.0 && !math.Signbit(f) {
		return 0.0, ErrPlus0MustBeEncodedWithZeroLengthValueBlock
	}
	return f, nil
}

func ParseBinaryFloat(v []byte) (float64, error) {
	var info byte
	var buf []byte
	info, v = v[0], v[1:]
	var base int
	switch info & 0x30 {
	case 0x00:
		base = 2
	case 0x10:
		base = 8
	case 0x20:
		base = 16
	case 0x30:
		return 0.0, ErrBits6And5OfInformationOctetAreEqualTo11
	}
	scale := uint((info & 0x0c) >> 2)
	var expLen int
	switch info & 0x03 {
	case 0x00:
		expLen = 1
	case 0x01:
		expLen = 2
	case 0x02:
		expLen = 3
	case 0x03:
		expLen = int(v[0])
		if expLen > 8 {
			return 0.0, ErrExponentTooLarge
		}
		v = v[1:]
	}
	buf, v = v[:expLen], v[expLen:]
	exponent, err := ParseInt64(buf)
	if err != nil {
		return 0.0, err
	}
	if len(v) > 8 {
		return 0.0, ErrMantissaTooLarge
	}
	mant, err := ParseInt64(v)
	if err != nil {
		return 0.0, err
	}
	mantissa := mant << scale
	if info&0x40 == 0x40 {
		mantissa = -mantissa
	}
	return float64(mantissa) * math.Pow(float64(base), float64(exponent)), nil
}

func ParseDecimalFloat(buf []byte) (float64, error) {
	var f float64
	switch buf[0] & 0x3F {
	case 0x01: // NR form 1
		i, err := strconv.ParseInt(strings.TrimLeft(string(buf[1:]), " "), 10, 64)
		if err != nil {
			return 0.0, err
		}
		f = float64(i)
	case 0x02, 0x03: // NR form 2, 3
		var err error
		f, err = strconv.ParseFloat(strings.Replace(strings.TrimLeft(string(buf[1:]), " "), ",", ".", -1), 64)
		if err != nil {
			return 0.0, err
		}
	default:
		return 0.0, ErrInvalidNRForm
	}
	if f == 0.0 && math.Signbit(f) {
		return 0.0, ErrNegative0MustBeEncodedAsASecialValue
	}
	return f, nil
}

func ParseSpecialFloat(buf []byte) (float64, error) {
	if len(buf) != 1 {
		return 0.0, ErrEncodingOfSpecialValueMustNotContainExponentAndMantissa
	}
	switch buf[0] {
	case 0x40:
		return math.Inf(1), nil
	case 0x41:
		return math.Inf(-1), nil
	case 0x42:
		return math.NaN(), nil
	case 0x43:
		return math.Copysign(0, -1), nil
	}
	return 0.0, ErrInvalidSpecialValueEncoding
}

// ParseGeneralizedTime parses a string value and if it conforms to
// GeneralizedTime[^0] format, will return a time.Time for that value.
//
// [^0]: https://www.itu.int/rec/T-REC-X.690-201508-I/en Section 11.7
func ParseGeneralizedTime(buf []byte) (time.Time, error) {
	var format string
	var fract time.Duration
	str := buf
	tzIndex := bytes.IndexAny(str, "Z+-")
	if tzIndex < 0 {
		return time.Time{}, ErrInvalidTimeFormat
	}
	dot := bytes.IndexAny(str, ".,")
	switch dot {
	case -1:
		switch tzIndex {
		case 10:
			format = `2006010215Z`
		case 12:
			format = `200601021504Z`
		case 14:
			format = `20060102150405Z`
		default:
			return time.Time{}, ErrInvalidTimeFormat
		}
	case 10, 12:
		if tzIndex < dot {
			return time.Time{}, ErrInvalidTimeFormat
		}
		// a "," is also allowed, but would not be parsed by time.Parse():
		str[dot] = '.'
		// If <minute> is omitted, then <fraction> represents a fraction of an
		// hour; otherwise, if <second> and <leap-second> are omitted, then
		// <fraction> represents a fraction of a minute; otherwise, <fraction>
		// represents a fraction of a second.
		// parse as float from dot to timezone
		f, err := strconv.ParseFloat(string(str[dot:tzIndex]), 64)
		if err != nil {
			return time.Time{}, ErrInvalidTimeFormat
		}
		// ...and strip that part
		str = append(str[:dot], str[tzIndex:]...)
		tzIndex = dot
		if dot == 10 {
			fract = time.Duration(int64(f * float64(time.Hour)))
			format = `2006010215Z`
		} else {
			fract = time.Duration(int64(f * float64(time.Minute)))
			format = `200601021504Z`
		}
	case 14:
		if tzIndex < dot {
			return time.Time{}, ErrInvalidTimeFormat
		}
		str[dot] = '.'
		// no need for fractional seconds, time.Parse() handles that
		format = `20060102150405Z`
	default:
		return time.Time{}, ErrInvalidTimeFormat
	}
	l := len(str)
	switch l - tzIndex {
	case 1:
		if str[l-1] != 'Z' {
			return time.Time{}, ErrInvalidTimeFormat
		}
	case 3:
		format += `0700`
		str = append(str, []byte("00")...)
	case 5:
		format += `0700`
	default:
		return time.Time{}, ErrInvalidTimeFormat
	}
	t, err := time.Parse(format, string(str))
	if err != nil {
		return time.Time{}, ErrInvalidTimeFormat
	}
	return t.Add(fract), nil
}

func ParseInt64(buf []byte) (int64, error) {
	var i int64
	if len(buf) > 8 {
		// We'll overflow an int64 in this case.
		return 0, ErrIntegerTooLarge
	}
	for n := 0; n < len(buf); n++ {
		i <<= 8
		i |= int64(buf[n])
	}
	// Shift up and down in order to sign extend the result.
	i <<= 64 - uint8(len(buf))*8
	i >>= 64 - uint8(len(buf))*8
	return i, nil
}

func EncodeIdentifier(class Class, typ Type, tag Tag) []byte {
	buf := []byte{uint8(class) | uint8(typ)}
	if tag < tagHigh {
		// Short-form
		buf[0] |= uint8(tag)
	} else {
		// high-tag-number
		buf[0] |= byte(tagHigh)
		buf = append(buf, EncodeTag(tag)...)
	}
	return buf
}

func EncodeTag(tag Tag) []byte {
	// set cap=4 to hopefully avoid additional allocations
	buf := make([]byte, 0, 4)
	for tag != 0 {
		// t := last 7 bits of tag (tagHighValueBitmask = 0x7F)
		t := tag & tagHighValueBitmask
		// right shift tag 7 to remove what was just pulled off
		tag >>= 7
		// if b already has entries this entry needs a continuation bit (0x80)
		if len(buf) != 0 {
			t |= tagHighContinueBitmask
		}
		buf = append(buf, byte(t))
	}
	// reverse
	// since bits were pulled off 'tag' small to high the byte slice is in reverse order.
	// example: tag = 0xFF results in {0x7F, 0x01 + 0x80 (continuation bit)}
	// this needs to be reversed into 0x81 0x7F
	for i, j := 0, len(buf)-1; i < len(buf)/2; i++ {
		buf[i], buf[j-i] = buf[j-i], buf[i]
	}
	return buf
}

func EncodeCount(n int) []byte {
	buf := EncodeUint64(uint64(n))
	if n > 127 || len(buf) > 1 {
		buf = append([]byte{longFormBitmaskLen | byte(len(buf))}, buf...)
	}
	return buf
}

func EncodeFloat64(f float64) []byte {
	switch {
	case math.IsInf(f, 1):
		return []byte{0x40}
	case math.IsInf(f, -1):
		return []byte{0x41}
	case math.IsNaN(f):
		return []byte{0x42}
	case f == 0.0:
		if math.Signbit(f) {
			return []byte{0x43}
		}
		return []byte{}
	}
	// we take the easy part ;-)
	buf := []byte(strconv.FormatFloat(f, 'G', -1, 64))
	if bytes.Contains(buf, []byte{'E'}) {
		return append([]byte{0x03}, buf...)
	}
	return append([]byte{0x02}, buf...)
}

func EncodeInt64(i int64) []byte {
	n := int64Len(i)
	buf := make([]byte, n)
	var j int
	for ; n > 0; n-- {
		buf[j] = byte(i >> uint((n-1)*8))
		j++
	}
	return buf
}

func EncodeUint64(i uint64) []byte {
	n := uint64Len(i)
	buf := make([]byte, n)
	var j int
	for ; n > 0; n-- {
		buf[j] = byte(i >> uint((n-1)*8))
		j++
	}
	return buf
}

func int64Len(i int64) int {
	n := 1
	for i > 127 {
		n++
		i >>= 8
	}
	for i < -128 {
		n++
		i >>= 8
	}
	return n
}

func uint64Len(i uint64) int {
	n := 1
	for i > 255 {
		n++
		i >>= 8
	}
	return n
}
