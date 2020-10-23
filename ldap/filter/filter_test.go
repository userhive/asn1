package filter

import (
	"strings"
	"testing"

	"github.com/userhive/asn1/ber"
)

func TestInvalid(t *testing.T) {
	t.Parallel()
	for i, s := range invalidTests() {
		if _, err := Compile(s); err == nil {
			t.Errorf("test %d Problem compiling %s - expected err", i, s)
		}
	}
}

func TestCompileDecompile(t *testing.T) {
	t.Parallel()
	for i, test := range compileTests() {
		p, err := Compile(test.s)
		switch {
		case err != nil && !strings.Contains(err.Error(), test.err):
			t.Errorf("test %d compile(%q) expected error %s, got: %v", i, test.s, test.err, err)
		case err == nil && test.err != "":
			t.Errorf("test %d compile(%q) expected error: %v", i, test.s, test.err)
		case err == nil && p.Tag != test.expT:
			t.Errorf("test %d compile(%q) expected %q, got: %q", i, test.s, test.expT, p.Tag)
		case err != nil:
			continue
		default:
			f, err := Decompile(p)
			switch {
			case err != nil:
				t.Errorf("test %d decompile(compile(%q)) expected no error, got : %v", i, test.s, err.Error())
			case test.expF != f:
				t.Errorf("test %d decompile(compile(%q)) expected %q, got: %q", i, test.s, test.expF, f)
			}
		}
	}
}

func TestEscape(t *testing.T) {
	if s, exp := Escape("a\x00b(c)d*e\\f"), `a\00b\28c\29d\2ae\5cf`; s != exp {
		t.Errorf("expected %q, got: %q", exp, s)
	}
	if s, exp := Escape("Lučić"), `Lu\c4\8di\c4\87`; s != exp {
		t.Errorf("expected %q, got: %q", exp, s)
	}
}

func TestUnescape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s   string
		err string
	}{
		{s: "a\u0100\x80", err: `error reading rune at position 3`},
		{s: `start\d`, err: `missing characters for escape in filter`},
		{s: `\`, err: `invalid characters for escape in filter: EOF`},
		{
			s:   `start\--end`,
			err: `invalid characters for escape in filter: encoding/hex: invalid byte: U+002D '-'`,
		},
		{
			s:   `start\d0\hh`,
			err: `invalid characters for escape in filter: encoding/hex: invalid byte: U+0068 'h'`,
		},
	}
	for i, test := range tests {
		res, err := Unescape([]byte(test.s))
		switch {
		case err == nil || err.Error() != test.err:
			t.Errorf("test %d unescape(%q) expected error %s, got: %v", i, test.s, test.err, err)
		case res != "":
			t.Errorf("test %d unescape(%q) expected non empty result", i, test.s)
		}
	}
}

func BenchmarkCompile(b *testing.B) {
	b.StopTimer()
	tests := compileTests()
	filters := make([]string, len(tests))
	for i, test := range tests {
		filters[i] = test.s
	}
	max := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Compile(filters[i%max])
	}
}

func BenchmarkDecompile(b *testing.B) {
	b.StopTimer()
	tests := compileTests()
	filters := make([]*ber.Packet, len(tests))
	for i, test := range tests {
		filters[i], _ = Compile(test.s)
	}
	max := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Decompile(filters[i%max])
	}
}

type compileTest struct {
	s    string
	expF string
	expT ber.Tag
	err  string
}

func compileTests() []compileTest {
	return []compileTest{
		{
			s:    "(&(sn=Miller)(givenName=Bob))",
			expF: "(&(sn=Miller)(givenName=Bob))",
			expT: And,
		},
		{
			s:    "(|(sn=Miller)(givenName=Bob))",
			expF: "(|(sn=Miller)(givenName=Bob))",
			expT: Or,
		},
		{
			s:    "(!(sn=Miller))",
			expF: "(!(sn=Miller))",
			expT: Not,
		},
		{
			s:    "(sn=Miller)",
			expF: "(sn=Miller)",
			expT: EqualityMatch,
		},
		{
			s:    "(sn=Mill*)",
			expF: "(sn=Mill*)",
			expT: Substrings,
		},
		{
			s:    "(sn=*Mill)",
			expF: "(sn=*Mill)",
			expT: Substrings,
		},
		{
			s:    "(sn=*Mill*)",
			expF: "(sn=*Mill*)",
			expT: Substrings,
		},
		{
			s:    "(sn=*i*le*)",
			expF: "(sn=*i*le*)",
			expT: Substrings,
		},
		{
			s:    "(sn=Mi*l*r)",
			expF: "(sn=Mi*l*r)",
			expT: Substrings,
		},
		// substring filters escape properly
		{
			s:    `(sn=Mi*함*r)`,
			expF: `(sn=Mi*\ed\95\a8*r)`,
			expT: Substrings,
		},
		// already escaped substring filters don't get double-escaped
		{
			s:    `(sn=Mi*\ed\95\a8*r)`,
			expF: `(sn=Mi*\ed\95\a8*r)`,
			expT: Substrings,
		},
		{
			s:    "(sn=Mi*le*)",
			expF: "(sn=Mi*le*)",
			expT: Substrings,
		},
		{
			s:    "(sn=*i*ler)",
			expF: "(sn=*i*ler)",
			expT: Substrings,
		},
		{
			s:    "(sn>=Miller)",
			expF: "(sn>=Miller)",
			expT: GreaterOrEqual,
		},
		{
			s:    "(sn<=Miller)",
			expF: "(sn<=Miller)",
			expT: LessOrEqual,
		},
		{
			s:    "(sn=*)",
			expF: "(sn=*)",
			expT: Present,
		},
		{
			s:    "(sn~=Miller)",
			expF: "(sn~=Miller)",
			expT: ApproxMatch,
		},
		{
			s:    `(objectGUID='\fc\fe\a3\ab\f9\90N\aaGm\d5I~\d12)`,
			expF: `(objectGUID='\fc\fe\a3\ab\f9\90N\aaGm\d5I~\d12)`,
			expT: EqualityMatch,
		},
		{
			s:    `(objectGUID=абвгдеёжзийклмнопрстуфхцчшщъыьэюя)`,
			expF: `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
			expT: EqualityMatch,
		},
		{
			s:    `(objectGUID=함수목록)`,
			expF: `(objectGUID=\ed\95\a8\ec\88\98\eb\aa\a9\eb\a1\9d)`,
			expT: EqualityMatch,
		},
		{
			s:    `(objectGUID=`,
			expF: ``,
			expT: 0,
			err:  "unexpected end of filter",
		},
		{
			s:    `(objectGUID=함수목록`,
			expF: ``,
			expT: 0,
			err:  "unexpected end of filter",
		},
		{
			s:    `((cn=)`,
			expF: ``,
			expT: 0,
			err:  "unexpected end of filter",
		},
		{
			s:    `(&(objectclass=inetorgperson)(cn=中文))`,
			expF: `(&(objectclass=inetorgperson)(cn=\e4\b8\ad\e6\96\87))`,
			expT: 0,
		},
		// attr extension
		{
			s:    `(memberOf:=foo)`,
			expF: `(memberOf:=foo)`,
			expT: ExtensibleMatch,
		},
		// attr+named matching rule extension
		{
			s:    `(memberOf:test:=foo)`,
			expF: `(memberOf:test:=foo)`,
			expT: ExtensibleMatch,
		},
		// attr+oid matching rule extension
		{
			s:    `(cn:1.2.3.4.5:=Fred Flintstone)`,
			expF: `(cn:1.2.3.4.5:=Fred Flintstone)`,
			expT: ExtensibleMatch,
		},
		// attr+dn+oid matching rule extension
		{
			s:    `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
			expF: `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
			expT: ExtensibleMatch,
		},
		// attr+dn extension
		{
			s:    `(o:dn:=Ace Industry)`,
			expF: `(o:dn:=Ace Industry)`,
			expT: ExtensibleMatch,
		},
		// dn extension
		{
			s:    `(:dn:2.4.6.8.10:=Dino)`,
			expF: `(:dn:2.4.6.8.10:=Dino)`,
			expT: ExtensibleMatch,
		},
		{
			s:    `(memberOf:1.2.840.113556.1.4.1941:=CN=User1,OU=blah,DC=mydomain,DC=net)`,
			expF: `(memberOf:1.2.840.113556.1.4.1941:=CN=User1,OU=blah,DC=mydomain,DC=net)`,
			expT: ExtensibleMatch,
		},
		// compileTest{ s: "()", filterType: ExtensibleMatch },
	}
}

func invalidTests() []string {
	return []string{
		`(objectGUID=\zz)`,
		`(objectGUID=\a)`,
	}
}
