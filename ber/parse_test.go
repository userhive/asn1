package asn1ber

import (
	"bytes"
	"math"
	"testing"
	"time"
)

func TestParseGeneralizedTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v   string
		exp time.Time
		err error
	}{
		{"20170222190527Z", time.Date(2017, time.Month(2), 22, 19, 05, 27, 0, time.UTC), nil},
		{"201702221905Z", time.Date(2017, time.Month(2), 22, 19, 05, 0, 0, time.UTC), nil},
		{"2017022219Z", time.Date(2017, time.Month(2), 22, 19, 0, 0, 0, time.UTC), nil},
		{"2017022219.25Z", time.Date(2017, time.Month(2), 22, 19, 15, 0, 0, time.UTC), nil},
		{"201702221905.25Z", time.Date(2017, time.Month(2), 22, 19, 5, 15, 0, time.UTC), nil},
		{"20170222190525-0100", time.Date(2017, time.Month(2), 22, 19, 5, 25, 0, time.FixedZone("", -3600)), nil},
		{"20170222190525+0100", time.Date(2017, time.Month(2), 22, 19, 5, 25, 0, time.FixedZone("", 3600)), nil},
		{"20170222190525+01", time.Date(2017, time.Month(2), 22, 19, 5, 25, 0, time.FixedZone("", 3600)), nil},
		{"20170222190527.123Z", time.Date(2017, time.Month(2), 22, 19, 05, 27, 123*1000*1000, time.UTC), nil},
		{"20170222190527,123Z", time.Date(2017, time.Month(2), 22, 19, 05, 27, 123*1000*1000, time.UTC), nil},
		{"2017022219-0100", time.Date(2017, time.Month(2), 22, 19, 0, 0, 0, time.FixedZone("", -3600)), nil},
	}
	for i, test := range tests {
		tt, err := ParseGeneralizedTime([]byte(test.v))
		switch {
		case err != nil && test.err == nil:
			t.Errorf("test %d: expected no error, got: %v", i, err)
		case err != nil && err != test.err:
			t.Errorf("test %d: expected error %v, got: %v", i, test.err, err)
		case !tt.Equal(test.exp):
			t.Errorf("test %d: expected %s, got: %s", i, test.exp, tt)
		}
	}
}

func TestParseInt64(t *testing.T) {
	t.Parallel()
	tests := []int64{
		0,
		10,
		128,
		1024,
		math.MaxInt64,
		-1,
		-100,
		-128,
		-1024,
		math.MinInt64,
	}
	for _, exp := range tests {
		i, err := ParseInt64(EncodeInt64(exp))
		if err != nil {
			t.Fatalf("error decoding %d: %v", exp, err)
		}
		if i != exp {
			t.Errorf("expected %d, got: %d", exp, i)
		}
	}
}

func TestParseHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v        []byte
		expN     int
		expClass Class
		expType  Type
		expTag   Tag
		expCount int
		err      string
	}{
		{ // empty
			v: []byte{}, err: "unexpected EOF",
		},
		{ // valid short form
			v:        []byte{byte(ClassUniversal) | byte(TypePrimitive) | byte(TagCharacterString), 127},
			expN:     2,
			expClass: ClassUniversal,
			expType:  TypePrimitive,
			expTag:   TagCharacterString,
			expCount: 127,
			err:      "",
		},
		{ // valid long form
			v: []byte{
				// 2-byte encoding of tag
				byte(ClassUniversal) | byte(TypePrimitive) | byte(tagHigh),
				byte(TagCharacterString),
				// 2-byte encoding of length
				longFormBitmaskLen | 1,
				127,
			},
			expN:     4,
			expClass: ClassUniversal,
			expType:  TypePrimitive,
			expTag:   TagCharacterString,
			expCount: 127,
			err:      "",
		},
		{ // valid indefinite length
			v: []byte{
				byte(ClassUniversal) | byte(TypeConstructed) | byte(TagCharacterString),
				longFormBitmaskLen,
			},
			expN:     2,
			expClass: ClassUniversal,
			expType:  TypeConstructed,
			expTag:   TagCharacterString,
			expCount: -1,
			err:      "",
		},
		{ // invalid indefinite length
			v: []byte{
				byte(ClassUniversal) | byte(TypePrimitive) | byte(TagCharacterString),
				longFormBitmaskLen,
			},
			expClass: ClassUniversal,
			expType:  TypePrimitive,
			expTag:   TagCharacterString,
			expN:     2,
			err:      "indefinite length used with primitive type",
		},
	}
	for i, test := range tests {
		n, class, typ, tag, count, err := ParseHeader(bytes.NewReader(test.v))
		switch {
		case err != nil && test.err == "":
			t.Errorf("test %d: unexpected error: %v", i, err)
		case err != nil && err.Error() != test.err:
			t.Errorf("test %d: expected error %v, got: %v", i, test.err, err)
		case err == nil && test.err != "":
			t.Errorf("test %d: expected error: %v", i, test.err)
		case n != test.expN:
			t.Errorf("test %d: expected read %d, got: %d", i, test.expN, n)
		case class != test.expClass:
			t.Errorf("test %d: expected class type %s, got: %s", i, test.expClass, class)
		case typ != test.expType:
			t.Errorf("test %d: expected tag type %s, got: %s", i, test.expType, typ)
		case tag != test.expTag:
			t.Errorf("test %d: expected tag %s, got %s", i, test.expTag, tag)
		case count != test.expCount:
			t.Errorf("test %d: expected count %d, got %d", i, test.expCount, count)
		}
	}
}

func TestParseIdentifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v        []byte
		expClass Class
		expType  Type
		expTag   Tag
		expN     int
		err      string
	}{
		{ // empty
			v:    []byte{},
			expN: 0,
			err:  "unexpected EOF",
		},
		{ // universal primitive eoc
			v:        []byte{byte(ClassUniversal) | byte(TypePrimitive) | byte(TagEOC)},
			expClass: ClassUniversal,
			expType:  TypePrimitive,
			expTag:   TagEOC,
			expN:     1,
		},
		{ // universal primitive character string
			v:        []byte{byte(ClassUniversal) | byte(TypePrimitive) | byte(TagCharacterString)},
			expClass: ClassUniversal,
			expType:  TypePrimitive,
			expTag:   TagCharacterString,
			expN:     1,
		},
		{ // universal constructed bit string
			v:        []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(TagBitString)},
			expClass: ClassUniversal,
			expType:  TypeConstructed,
			expTag:   TagBitString,
			expN:     1,
		},
		{ // universal constructed character string
			v:        []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(TagCharacterString)},
			expClass: ClassUniversal,
			expType:  TypeConstructed,
			expTag:   TagCharacterString,
			expN:     1,
		},
		{ // application constructed object descriptor
			v:        []byte{byte(ClassApplication) | byte(TypeConstructed) | byte(TagObjectDescriptor)},
			expClass: ClassApplication,
			expType:  TypeConstructed,
			expTag:   TagObjectDescriptor,
			expN:     1,
		},
		{ // context constructed object descriptor
			v:        []byte{byte(ClassContext) | byte(TypeConstructed) | byte(TagObjectDescriptor)},
			expClass: ClassContext,
			expType:  TypeConstructed,
			expTag:   TagObjectDescriptor,
			expN:     1,
		},
		{ // private constructed object descriptor
			v:        []byte{byte(ClassPrivate) | byte(TypeConstructed) | byte(TagObjectDescriptor)},
			expClass: ClassPrivate,
			expType:  TypeConstructed,
			expTag:   TagObjectDescriptor,
			expN:     1,
		},
		{ // high-tag-number tag missing bytes
			v:    []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh)},
			expN: 1,
			err:  "unexpected EOF",
		},
		{ // high-tag-number tag invalid first byte
			v:    []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh), 0x0},
			expN: 2,
			err:  "invalid high byte",
		},
		{ // high-tag-number tag invalid first byte with continue bit
			v:    []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh), byte(tagHighContinueBitmask)},
			expN: 2,
			err:  "invalid high byte",
		},
		{ // high-tag-number tag continuation missing bytes
			v:    []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh), byte(tagHighContinueBitmask | 0x1)},
			expN: 2,
			err:  "unexpected EOF",
		},
		{ // high-tag-number tag overflow
			v: []byte{
				byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh),
				byte(tagHighContinueBitmask | 0x1),
				byte(tagHighContinueBitmask | 0x1),
				byte(tagHighContinueBitmask | 0x1),
				byte(tagHighContinueBitmask | 0x1),
				byte(tagHighContinueBitmask | 0x1),
				byte(tagHighContinueBitmask | 0x1),
				byte(tagHighContinueBitmask | 0x1),
				byte(tagHighContinueBitmask | 0x1),
				byte(tagHighContinueBitmask | 0x1),
				byte(0x1),
			},
			expN: 11,
			err:  "tag value overflow",
		},
		{ // max high-tag-number tag
			v: []byte{
				byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(0x7f),
			},
			expClass: ClassUniversal,
			expType:  TypeConstructed,
			expTag:   Tag(0x7FFFFFFFFFFFFFFF), // 01111111...(63)...11111b
			expN:     10,
		},
		{ // high-tag-number encoding of low-tag value
			v: []byte{
				byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh),
				byte(TagObjectDescriptor),
			},
			expClass: ClassUniversal,
			expType:  TypeConstructed,
			expTag:   TagObjectDescriptor,
			expN:     2,
		},
		{ // max high-tag-number tag ignores extra data
			v: []byte{
				byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(0x7f),
				byte(0x01), // extra data, shouldn't be read
				byte(0x02), // extra data, shouldn't be read
				byte(0x03), // extra data, shouldn't be read
			},
			expClass: ClassUniversal,
			expType:  TypeConstructed,
			expTag:   Tag(0x7FFFFFFFFFFFFFFF), // 01111111...(63)...11111b
			expN:     10,
		},
	}
	for i, test := range tests {
		n, class, typ, tag, err := ParseIdentifier(bytes.NewReader(test.v))
		switch {
		case err != nil && test.err == "":
			t.Errorf("test %d: unexpected error: %v", i, err)
		case err != nil && err.Error() != test.err:
			t.Errorf("test %d: expected error %v, got: %v", i, test.err, err)
		case err == nil && test.err != "":
			t.Errorf("test %d: expected error %v", i, test.err)
		case n != test.expN:
			t.Errorf("test %d: expected read %d, got: %d", i, test.expN, n)
		case class != test.expClass:
			t.Errorf("test %d: expected class %s, got: %s", i, test.expClass, class)
		case typ != test.expType:
			t.Errorf("test %d: expected tag %s, got: %s", i, test.expType, typ)
		case tag != test.expTag:
			t.Errorf("test %d: expected tag %s, got: %s", i, test.expTag, tag)
		}
	}
}

func TestParseCount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v        []byte
		expN     int
		expCount int64
		err      string
	}{
		{ // empty
			v: []byte{}, expN: 0, err: "unexpected EOF",
		},
		{ // invalid first byte
			v: []byte{0xFF}, expN: 1, err: "invalid length",
		},
		{ // indefinite form
			v: []byte{longFormBitmaskLen}, expN: 1, expCount: -1,
		},
		{ // short-definite-form zero length
			v: []byte{0}, expN: 1, expCount: 0,
		},
		{ // short-definite-form length 1
			v: []byte{1}, expN: 1, expCount: 1,
		},
		{ // short-definite-form max length
			v: []byte{127}, expN: 1, expCount: 127,
		},
		{ // long-definite-form missing bytes
			v: []byte{longFormBitmaskLen | 1}, expN: 1, err: "unexpected EOF",
		},
		{ // long-definite-form overflow
			v: []byte{longFormBitmaskLen | 9}, expN: 1, err: "length value overflow",
		},
		{ // long-definite-form zero length
			v: []byte{longFormBitmaskLen | 1, 0x0}, expN: 2,
		},
		{ // long-definite-form length 127
			v: []byte{longFormBitmaskLen | 1, 127}, expN: 2, expCount: 127,
		},
		{ // long-definite-form max length (32-bit)
			v: []byte{longFormBitmaskLen | 4, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF}, expN: 5, expCount: math.MaxInt32,
		},
		{ // long-definite-form max length (64-bit)
			v: []byte{longFormBitmaskLen | 8, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, expN: 9, expCount: math.MaxInt64,
		},
	}
	for i, test := range tests {
		// Skip tests requiring 64-bit integers on platforms that don't support them
		if test.expCount != int64(int(test.expCount)) {
			continue
		}
		n, count, err := ParseCount(bytes.NewReader(test.v))
		switch {
		case err != nil && test.err == "":
			t.Errorf("test %d: expected no error, got: %v", i, err)
		case err != nil && err.Error() != test.err:
			t.Errorf("test %d: expected error %v, got %v", i, test.err, err)
		case err == nil && test.err != "":
			t.Errorf("test %d: expected error %v", i, test.err)
		case n != test.expN:
			t.Errorf("test %d: expected read %d, got %d", i, test.expN, n)
		case int64(count) != test.expCount:
			t.Errorf("test %d: expected count %d, got %d", i, test.expCount, count)
		}
	}
}

func TestEncodeIdentifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Class Class
		Type  Type
		Tag   Tag
		exp   []byte
	}{
		{ // universal primitive eoc
			Class: ClassUniversal,
			Type:  TypePrimitive,
			Tag:   TagEOC,
			exp:   []byte{byte(ClassUniversal) | byte(TypePrimitive) | byte(TagEOC)},
		},
		{ // universal primitive character string
			Class: ClassUniversal,
			Type:  TypePrimitive,
			Tag:   TagCharacterString,
			exp:   []byte{byte(ClassUniversal) | byte(TypePrimitive) | byte(TagCharacterString)},
		},
		{ // universal constructed bit string
			Class: ClassUniversal,
			Type:  TypeConstructed,
			Tag:   TagBitString,
			exp:   []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(TagBitString)},
		},
		{ // universal constructed character string
			Class: ClassUniversal,
			Type:  TypeConstructed,
			Tag:   TagCharacterString,
			exp:   []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(TagCharacterString)},
		},
		{ // application constructed object descriptor
			Class: ClassApplication,
			Type:  TypeConstructed,
			Tag:   TagObjectDescriptor,
			exp:   []byte{byte(ClassApplication) | byte(TypeConstructed) | byte(TagObjectDescriptor)},
		},
		{ // context constructed object descriptor
			Class: ClassContext,
			Type:  TypeConstructed,
			Tag:   TagObjectDescriptor,
			exp:   []byte{byte(ClassContext) | byte(TypeConstructed) | byte(TagObjectDescriptor)},
		},
		{ // private constructed object descriptor
			Class: ClassPrivate,
			Type:  TypeConstructed,
			Tag:   TagObjectDescriptor,
			exp:   []byte{byte(ClassPrivate) | byte(TypeConstructed) | byte(TagObjectDescriptor)},
		},
		{ // max low-tag-number tag
			Class: ClassUniversal,
			Type:  TypeConstructed,
			Tag:   TagBMPString,
			exp:   []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(TagBMPString)},
		},
		{ // min high-tag-number tag
			Class: ClassUniversal,
			Type:  TypeConstructed,
			Tag:   TagBMPString + 1,
			exp:   []byte{byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh), byte(TagBMPString + 1)},
		},
		{ // max high-tag-number tag
			Class: ClassUniversal,
			Type:  TypeConstructed,
			Tag:   Tag(math.MaxInt64),
			exp: []byte{
				byte(ClassUniversal) | byte(TypeConstructed) | byte(tagHigh),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(tagHighContinueBitmask | 0x7f),
				byte(0x7f),
			},
		},
	}
	for i, test := range tests {
		buf := EncodeIdentifier(test.Class, test.Type, test.Tag)
		if !bytes.Equal(test.exp, buf) {
			t.Errorf("test %d: expected\n\t%#v\ngot\n\t%#v", i, test.exp, buf)
		}
	}
}

func TestEncodeTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tag Tag
		exp []byte
	}{
		{134, []byte{0x80 + 0x01, 0x06}},
		{123456, []byte{0x80 + 0x07, 0x80 + 0x44, 0x40}},
		{0xFF, []byte{0x81, 0x7F}},
	}
	for _, test := range tests {
		if buf := EncodeTag(test.tag); !bytes.Equal(test.exp, buf) {
			t.Errorf("tag: %d exp: %#v got: %#v", test.tag, test.exp, buf)
		}
	}
}

func TestEncodeCount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n   int64
		exp []byte
	}{
		{ // 0
			n:   0,
			exp: []byte{0},
		},
		{ // 1
			n:   1,
			exp: []byte{1},
		},
		{ // max short-form length
			n:   127,
			exp: []byte{127},
		},
		{ // min long-form length
			n:   128,
			exp: []byte{longFormBitmaskLen | 1, 128},
		},
		{ // max long-form length (32-bit)
			n: math.MaxInt32,
			exp: []byte{
				longFormBitmaskLen | 4,
				0x7F,
				0xFF,
				0xFF,
				0xFF,
			},
		},
		{ // max long-form length (64-bit)
			n: math.MaxInt64,
			exp: []byte{
				longFormBitmaskLen | 8,
				0x7F,
				0xFF,
				0xFF,
				0xFF,
				0xFF,
				0xFF,
				0xFF,
				0xFF,
			},
		},
	}
	for i, test := range tests {
		// Skip tests requiring 64-bit integers on platforms that don't support them
		if test.n != int64(int(test.n)) {
			continue
		}
		b := EncodeCount(int(test.n))
		if !bytes.Equal(test.exp, b) {
			t.Errorf("test %d: Expected\n\t%#v\ngot\n\t%#v", i, test.exp, b)
		}
	}
}

func TestEncodeFloat64(t *testing.T) {
	t.Parallel()
	tests := []float64{
		0.15625,
		-0.15625,
		math.Inf(1),
		math.Inf(-1),
		math.NaN(),
		math.Copysign(0, -1), // -0
		0.0,
	}
	for _, v := range tests {
		enc := EncodeFloat64(v)
		dec, err := ParseReal(enc)
		if err != nil {
			t.Errorf("Failed to decode %f (%v): %s", v, enc, err)
		}
		if dec != v {
			if !(math.IsNaN(dec) && math.IsNaN(v)) {
				t.Errorf("decoded value != orig: %f <=> %f", v, dec)
			}
		}
	}
}
