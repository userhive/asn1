package ldaputil

import (
	"reflect"
	"testing"
)

func TestParseDNBad(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"*":                       "DN ended with incomplete type, value pair",
		"cn=Jim\\0Test":           "failed to decode escaped character: encoding/hex: invalid byte: U+0054 'T'",
		"cn=Jim\\0":               "got corrupted escaped character",
		"DC=example,=net":         "DN ended with incomplete type, value pair",
		"1=#0402486":              "failed to decode BER encoding: encoding/hex: odd length hex string",
		"test,DC=example,DC=com":  "incomplete type, value pair",
		"=test,DC=example,DC=com": "incomplete type, value pair",
	}
	for i, test := range tests {
		_, err := ParseDN(i)
		if err == nil {
			t.Errorf("Expected %s to fail parsing but succeeded\n", i)
		} else if err.Error() != test {
			t.Errorf("Unexpected error on %s:\n%s\nvs.\n%s\n", i, test, err.Error())
		}
	}
}

func TestParseDN(t *testing.T) {
	t.Parallel()
	tests := map[string]DN{
		"": {[]*RelativeDN{}},
		"cn=Jim\\2C \\22Hasse Hö\\22 Hansson!,dc=dummy,dc=com": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "Jim, \"Hasse Hö\" Hansson!"}}},
			{[]*AttributeTypeAndValue{{"dc", "dummy"}}},
			{[]*AttributeTypeAndValue{{"dc", "com"}}},
		}},
		"UID=jsmith,DC=example,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"UID", "jsmith"}}},
			{[]*AttributeTypeAndValue{{"DC", "example"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}},
		}},
		"OU=Sales+CN=J. Smith,DC=example,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"OU", "Sales"},
				{"CN", "J. Smith"},
			}},
			{[]*AttributeTypeAndValue{{"DC", "example"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}},
		}},
		"1.3.6.1.4.1.1466.0=#04024869": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", "Hi"}}},
		}},
		"1.3.6.1.4.1.1466.0=#04024869,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", "Hi"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}},
		}},
		"CN=Lu\\C4\\8Di\\C4\\87": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"CN", "Lučić"}}},
		}},
		"  CN  =  Lu\\C4\\8Di\\C4\\87  ": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"CN", "Lučić"}}},
		}},
		`   A   =   1   ,   B   =   2   `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"A", "1"}}},
			{[]*AttributeTypeAndValue{{"B", "2"}}},
		}},
		`   A   =   1   +   B   =   2   `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"A", "1"},
				{"B", "2"},
			}},
		}},
		`   \ \ A\ \    =   \ \ 1\ \    ,   \ \ B\ \    =   \ \ 2\ \    `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"  A  ", "  1  "}}},
			{[]*AttributeTypeAndValue{{"  B  ", "  2  "}}},
		}},
		`   \ \ A\ \    =   \ \ 1\ \    +   \ \ B\ \    =   \ \ 2\ \    `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"  A  ", "  1  "},
				{"  B  ", "  2  "},
			}},
		}},
	}
	for i, test := range tests {
		dn, err := ParseDN(i)
		if err != nil {
			t.Errorf(err.Error())
			continue
		}
		if !reflect.DeepEqual(dn, &test) {
			t.Errorf("Parsed DN %s is not equal to the expected structure", i)
			t.Logf("Expected:")
			for _, rdn := range test.RDNs {
				for _, attribs := range rdn.Attributes {
					t.Logf("#%v\n", attribs)
				}
			}
			t.Logf("Actual:")
			for _, rdn := range dn.RDNs {
				for _, attribs := range rdn.Attributes {
					t.Logf("#%v\n", attribs)
				}
			}
		}
	}
}

func TestParseDNEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		A     string
		B     string
		Equal bool
	}{
		// Exact match
		{"", "", true},
		{"o=A", "o=A", true},
		{"o=A", "o=B", false},
		{"o=A,o=B", "o=A,o=B", true},
		{"o=A,o=B", "o=A,o=C", false},
		{"o=A+o=B", "o=A+o=B", true},
		{"o=A+o=B", "o=A+o=C", false},
		// Case mismatch in type is ignored
		{"o=A", "O=A", true},
		{"o=A,o=B", "o=A,O=B", true},
		{"o=A+o=B", "o=A+O=B", true},
		// Case mismatch in value is significant
		{"o=a", "O=A", false},
		{"o=a,o=B", "o=A,O=B", false},
		{"o=a+o=B", "o=A+O=B", false},
		// Multi-valued RDN order mismatch is ignored
		{"o=A+o=B", "O=B+o=A", true},
		// Number of RDN attributes is significant
		{"o=A+o=B", "O=B+o=A+O=B", false},
		// Missing values are significant
		{"o=A+o=B", "O=B+o=A+O=C", false}, // missing values matter
		{"o=A+o=B+o=C", "O=B+o=A", false}, // missing values matter
		// Whitespace tests
		// Matching
		{
			"cn=John Doe, ou=People, dc=sun.com",
			"cn=John Doe, ou=People, dc=sun.com",
			true,
		},
		// Difference in leading/trailing chars is ignored
		{
			"cn=John Doe, ou=People, dc=sun.com",
			"cn=John Doe,ou=People,dc=sun.com",
			true,
		},
		// Difference in values is significant
		{
			"cn=John Doe, ou=People, dc=sun.com",
			"cn=John  Doe, ou=People, dc=sun.com",
			false,
		},
	}
	for i, test := range tests {
		a, err := ParseDN(test.A)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		b, err := ParseDN(test.B)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if expected, actual := test.Equal, a.Equal(b); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, test.A, test.B, expected, actual)
			continue
		}
		if expected, actual := test.Equal, b.Equal(a); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, test.A, test.B, expected, actual)
			continue
		}
	}
}

func TestParseDNAncestor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		A        string
		B        string
		Ancestor bool
	}{
		// Exact match returns false
		{"", "", false},
		{"o=A", "o=A", false},
		{"o=A,o=B", "o=A,o=B", false},
		{"o=A+o=B", "o=A+o=B", false},
		// Mismatch
		{"ou=C,ou=B,o=A", "ou=E,ou=D,ou=B,o=A", false},
		// Descendant
		{"ou=C,ou=B,o=A", "ou=E,ou=C,ou=B,o=A", true},
	}
	for i, test := range tests {
		a, err := ParseDN(test.A)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		b, err := ParseDN(test.B)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if expected, actual := test.Ancestor, a.AncestorOf(b); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, test.A, test.B, expected, actual)
			continue
		}
	}
}
