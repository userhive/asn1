package ber

import (
	"bytes"
	"io/ioutil"
	"math"
	"testing"
)

func TestNewBoolean(t *testing.T) {
	t.Parallel()
	p := NewBoolean(ClassUniversal, TypePrimitive, TagBoolean, true)
	b, ok := p.Value.(bool)
	if !ok || b != true {
		t.Error("error during creating packet")
	}
	p2, err := ParseBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	b, ok = p2.Value.(bool)
	if !ok || b != true {
		t.Error("expected true")
	}
}

func TestNewLDAPBoolean(t *testing.T) {
	t.Parallel()
	p := NewLDAPBoolean(ClassUniversal, TypePrimitive, TagBoolean, true)
	b, ok := p.Value.(bool)
	if !ok || b != true {
		t.Error("error during creating packet")
	}
	p2, err := ParseBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	b, ok = p2.Value.(bool)
	if !ok || b != true {
		t.Error("expected true")
	}
}

func TestNewSequence(t *testing.T) {
	t.Parallel()
	tests := []string{
		"HIC SVNT LEONES",
		"Iñtërnâtiônàlizætiøn",
		"Terra Incognita",
	}
	s := NewSequence()
	for _, v := range tests {
		s.AppendChild(NewString(ClassUniversal, TypePrimitive, TagOctetString, v))
	}
	if len(s.Children) != len(tests) {
		t.Errorf("expected len(children)==len(tests): %d!=%d", len(tests), len(s.Children))
	}
	p, err := ParseBytes(s.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != len(tests) {
		t.Errorf("expected len(children)==len(tests): %d!=%d", len(tests), len(p.Children))
	}
	for i, s := range tests {
		if p.Children[i].Value.(string) != s {
			t.Errorf("expected %d to be %q, got: %q", i, s, p.Children[i].Value.(string))
		}
	}
}

func TestNewString(t *testing.T) {
	t.Parallel()
	p := NewString(ClassUniversal, TypePrimitive, TagOctetString, "Ad impossibilia nemo tenetur")
	p2, err := ParseBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	p2.ByteValue = nil
	if !bytes.Equal(p2.ByteValue, p.ByteValue) {
		t.Error("packets should be the same")
	}
}

func TestNewStringUTF8(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v   string
		err string
	}{
		{"åäöüß", ""},
		{"asdfg\xFF", "invalid UTF-8 string"},
	}
	for i, test := range tests {
		p := NewString(ClassUniversal, TypePrimitive, TagUTF8String, test.v)
		s, err := ParseBytes(p.Bytes())
		switch {
		case err != nil && test.err == "":
			t.Errorf("test %d: expected no error for %q, got: %v", i, test.v, err)
		case err != nil && err.Error() != test.err:
			t.Errorf("test %d: expected error %s for %q, got: %v", i, test.err, test.v, err)
		case err == nil && test.err != "":
			t.Errorf("test %d: expected error %s", i, test.err)
		case err == nil && s.Value.(string) != test.v:
			t.Errorf("test %d: expected %q, got: %q", i, test.v, s.Value.(string))
		}
	}
}

func TestNewStringIA5(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v   string
		err string
	}{
		{"asdfgh", ""},
		{"asdfgå", "invalid IA5 string"},
	}
	for i, test := range tests {
		p := NewString(ClassUniversal, TypePrimitive, TagIA5String, test.v)
		s, err := ParseBytes(p.Bytes())
		switch {
		case err != nil && test.err == "":
			t.Errorf("test %d: expected no error for %q, got: %v", i, test.v, err)
		case err != nil && err.Error() != test.err:
			t.Errorf("test %d: expected error %s for %q, got: %v", i, test.err, test.v, err)
		case err == nil && test.err != "":
			t.Errorf("test %d: expected error %s", i, test.err)
		case err == nil && s.Value.(string) != test.v:
			t.Errorf("test %d: expected %q, got: %q", i, test.v, s.Value.(string))
		}
	}
}

func TestNewStringPrintable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v   string
		err string
	}{
		{"asdfgh", ""},
		{"asdfgå", "invalid Printable string"},
	}
	for i, test := range tests {
		p := NewString(ClassUniversal, TypePrimitive, TagPrintableString, test.v)
		s, err := ParseBytes(p.Bytes())
		switch {
		case err != nil && test.err == "":
			t.Errorf("test %d: expected no error for %q, got: %v", i, test.v, err)
		case err != nil && err.Error() != test.err:
			t.Errorf("test %d: expected error %s for %q, got: %v", i, test.err, test.v, err)
		case err == nil && test.err != "":
			t.Errorf("test %d: expected error %s", i, test.err)
		case err == nil && s.Value.(string) != test.v:
			t.Errorf("test %d: expected %q, got: %q", i, test.v, s.Value.(string))
		}
	}
}

func TestNewStringOctet(t *testing.T) {
	t.Parallel()
	// data src : http://luca.ntop.org/Teaching/Appunti/asn1.html 5.10
	exp := []byte{0x04, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	v := NewString(ClassUniversal, TypePrimitive, TagOctetString, "\x01\x23\x45\x67\x89\xab\xcd\xef")
	if !bytes.Equal(v.Bytes(), exp) {
		t.Error("expected strings to match")
	}
}

func TestNewInteger(t *testing.T) {
	t.Parallel()
	// data src : http://luca.ntop.org/Teaching/Appunti/asn1.html 5.7
	tests := []struct {
		v   int64
		exp []byte
	}{
		{v: 0, exp: []byte{0x02, 0x01, 0x00}},
		{v: 127, exp: []byte{0x02, 0x01, 0x7F}},
		{v: 128, exp: []byte{0x02, 0x02, 0x00, 0x80}},
		{v: 256, exp: []byte{0x02, 0x02, 0x01, 0x00}},
		{v: -128, exp: []byte{0x02, 0x01, 0x80}},
		{v: -129, exp: []byte{0x02, 0x02, 0xFF, 0x7F}},
		{v: math.MaxInt64, exp: []byte{0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{v: math.MinInt64, exp: []byte{0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, test := range tests {
		if i := NewInteger(ClassUniversal, TypePrimitive, TagInteger, test.v).Bytes(); !bytes.Equal(test.exp, i) {
			t.Errorf("Wrong binary generated for %d : got % X, expected % X", test.v, i, test.exp)
		}
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	for _, test := range parseTests() {
		buf, err := ioutil.ReadFile("testdata/" + test.f)
		if err != nil {
			t.Errorf("unable to load %s: %v", test.f, err)
			continue
		}
		_, p, err := Parse(bytes.NewReader(buf))
		switch {
		case err != nil && test.err == "":
			t.Errorf("%s: unexpected error: %v", test.f, err)
			continue
		case err != nil && test.err != err.Error():
			t.Errorf("%s: expected error %q, got: %q", test.f, test.err, err)
			continue
		case err != nil && test.err == err.Error():
			continue
		case err == nil && test.err != "":
			t.Errorf("%s: expected error: %q", test.f, test.err)
			continue
		}
		out := p.Bytes()
		if test.abnormal || test.indefinite {
			// Abnormal encodings and encodings that used indefinite length
			// should re-encode differently
			if bytes.Equal(out, buf) {
				t.Errorf("%s: data should have been re-encoded differently", test.f)
			}
		} else if !bytes.Equal(out, buf) {
			// Make sure the serialized data matches the source
			t.Errorf("%s: data should be the same\nwant: %#v\ngot: %#v", test.f, buf, out)
		}
		p, err = ParseBytes(out)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", test.f, err)
			continue
		}
		// Make sure the re-serialized data matches our original serialization
		out2 := p.Bytes()
		if !bytes.Equal(out, out2) {
			t.Errorf("%s: data should be the same\nwant: %#v\ngot: %#v", test.f, out, out2)
		}
	}
}

func TestParseBytes(t *testing.T) {
	t.Parallel()
	for _, test := range parseTests() {
		buf, err := ioutil.ReadFile("testdata/" + test.f)
		if err != nil {
			t.Errorf("unable to load %s: %v", test.f, err)
			continue
		}
		p, err := ParseBytes(buf)
		switch {
		case err != nil && test.err == "":
			t.Errorf("%s: unexpected error: %v", test.f, err)
			continue
		case err != nil && test.err != err.Error():
			t.Errorf("%s: expected error %q, got: %q", test.f, test.err, err)
			continue
		case err != nil && test.err == err.Error():
			continue
		case err == nil && test.err != "":
			t.Errorf("%s: expected error %q", test.f, test.err)
			continue
		}
		out := p.Bytes()
		if test.abnormal || test.indefinite {
			// Abnormal encodings and encodings that used indefinite length
			// should re-encode differently
			if bytes.Equal(out, buf) {
				t.Errorf("%s: data should have been re-encoded differently", test.f)
			}
		} else if !bytes.Equal(out, buf) {
			// Make sure the serialized data matches the source
			t.Errorf("%s: data should be the same\nwant: %#v\ngot: %#v", test.f, buf, out)
		}
		p, err = ParseBytes(out)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", test.f, err)
			continue
		}
		// Make sure the re-serialized data matches our original serialization
		out2 := p.Bytes()
		if !bytes.Equal(out, out2) {
			t.Errorf("%s: data should be the same\nwant: %#v\ngot: %#v", test.f, out, out2)
		}
	}
}

func TestNewIntegerParse(t *testing.T) {
	t.Parallel()
	exp := int64(10)
	p := NewInteger(ClassUniversal, TypePrimitive, TagInteger, exp)
	i, ok := p.Value.(int64)
	if !ok || i != exp {
		t.Error("error creating packet")
	}
	p2, err := ParseBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	i, ok = p2.Value.(int64)
	if !ok || i != exp {
		t.Error("error decoding packet")
	}
}

func TestNewStringParse(t *testing.T) {
	t.Parallel()
	exp := "Hic sunt dracones"
	p := NewString(ClassUniversal, TypePrimitive, TagOctetString, exp)
	v, ok := p.Value.(string)
	if !ok || v != exp {
		t.Errorf("expected %q, got: %q", exp, v)
	}
	p2, err := ParseBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	v, ok = p2.Value.(string)
	if !ok || v != exp {
		t.Errorf("expected %q, got: %q", exp, v)
	}
}

type parseTest struct {
	// file contains the path to the ber-encoded file
	f string
	// err indicates whether a decoding error is expected
	err string
	// abnormal indicates whether a normalized re-encoding is expected to
	// differ from the original source
	abnormal bool
	// indefinite indicates the source file used indefinite-length encoding, so
	// the re-encoding is expected to differ (since the length is known)
	indefinite bool
}

// Tests from http://www.strozhevsky.com/free_docs/free_asn1_testsuite_descr.pdf
// Source files and descriptions at http://www.strozhevsky.com/free_docs/TEST_SUITE.zip
func parseTests() []parseTest {
	return []parseTest{
		// Common blocks
		{f: "tc1.ber", err: "tag value overflow"},
		{f: "tc2.ber", err: "unexpected EOF"},
		{f: "tc3.ber", err: "unexpected EOF"},
		{f: "tc4.ber", err: "invalid length"},
		{f: "tc5.ber", err: "", abnormal: true},
		// Real numbers (some expected failures are disabled until support is added)
		{f: "tc6.ber", err: "+0 must be encoded with zero-length value block"},
		{f: "tc7.ber", err: "-0 must be encoded as a special value"},
		{f: "tc8.ber", err: "encoding of special value must not contain exponent and mantissa"},
		{f: "tc9.ber", err: "bits 6 and 5 of information octet are equal to 11"},
		{f: "tc10.ber", err: ""},
		{f: "tc11.ber", err: "invalid NR form"},
		{f: "tc12.ber", err: "invalid special value encoding"},
		{f: "tc13.ber", err: "unexpected EOF"},
		{f: "tc14.ber", err: "unexpected EOF"},
		{f: "tc15.ber", err: "exponent too large"},
		{f: "tc16.ber", err: "mantissa too large"},
		{f: "tc17.ber", err: "exponent too large"}, // Error: "Too big values for exponent and mantissa + using of "scaling factor" value"
		// Integers
		{f: "tc18.ber", err: ""},
		{f: "tc19.ber", err: "unexpected EOF"},
		{f: "tc20.ber", err: ""},
		// Object identifiers
		{f: "tc21.ber", err: ""},
		{f: "tc22.ber", err: ""},
		{f: "tc23.ber", err: "unexpected EOF"},
		{f: "tc24.ber", err: ""},
		// Booleans
		{f: "tc25.ber", err: ""},
		{f: "tc26.ber", err: ""},
		{f: "tc27.ber", err: "unexpected EOF"},
		{f: "tc28.ber", err: ""},
		{f: "tc29.ber", err: ""},
		// Null
		{f: "tc30.ber", err: ""},
		{f: "tc31.ber", err: "unexpected EOF"},
		{f: "tc32.ber", err: ""},
		// Bit string (some expected failures are disabled until support is added)
		{f: "tc33.ber", err: ""}, // Error: "Too big value for "unused bits""
		{f: "tc34.ber", err: "unexpected EOF"},
		{f: "tc35.ber", err: "", indefinite: true}, // Error: "Using of different from BIT STRING types as internal types for constructive encoding"
		{f: "tc36.ber", err: "", indefinite: true}, // Error: "Using of "unused bits" in internal BIT STRINGs with constructive form of encoding"
		{f: "tc37.ber", err: ""},
		{f: "tc38.ber", err: "", indefinite: true},
		{f: "tc39.ber", err: ""},
		{f: "tc40.ber", err: ""},
		// Octet string (some expected failures are disabled until support is added)
		{f: "tc41.ber", err: "", indefinite: true}, // Error: "Using of different from OCTET STRING types as internal types for constructive encoding"
		{f: "tc42.ber", err: "unexpected EOF"},
		{f: "tc43.ber", err: "unexpected EOF"},
		{f: "tc44.ber", err: ""},
		{f: "tc45.ber", err: ""},
		// Bit string
		{f: "tc46.ber", err: "indefinite length used with primitive type"},
		{f: "tc47.ber", err: "EOC child not allowed with definite length"},
		{f: "tc48.ber", err: "", indefinite: true}, // Error: "Using of more than 7 "unused bits" in BIT STRING with constrictive encoding form"
		{f: "tc49.ber", err: ""},
		{f: "tc50.ber", err: is64bit("length cannot be less than -1", "length value overflow")},
		{f: "tc51.ber", err: is64bit("length greater than max", "length value overflow")},
	}
}

func is64bit(a, b string) string {
	maxInt64 := int64(math.MaxInt64)
	length := int(maxInt64)
	if int64(length) != maxInt64 {
		return b
	}
	return a
}
