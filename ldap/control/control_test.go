package control

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/userhive/asn1/ber"
)

func TestEncodeDecode(t *testing.T) {
	t.Parallel()
	tests := []Control{
		NewManageDsaIT(false),
		NewManageDsaIT(true),
		NewMicrosoftChangeNotification(),
		NewMicrosoftShowDeletedObjects(),
		NewPaging(0),
		NewPaging(100),
		NewString("x", false, ""),
		NewString("x", false, "y"),
		NewString("x", true, ""),
		NewString("x", true, "y"),
	}
	for i, test := range tests {
		p := test.Encode()
		encodedBytes := p.Bytes()
		// Decode directly from the encoded packet (ensures Value is correct)
		fromPacket, err := Decode(p)
		if err != nil {
			t.Errorf("test %d decoding encoded bytes control failed: %s", i, err)
		}
		if !bytes.Equal(encodedBytes, fromPacket.Encode().Bytes()) {
			t.Errorf("test %d round-trip from encoded packet failed", i)
		}
		if reflect.TypeOf(test) != reflect.TypeOf(fromPacket) {
			t.Errorf("test %d got different type decoding from encoded packet: %T vs %T", i, fromPacket, test)
		}
		// Decode from the wire bytes (ensures ber-encoding is correct)
		dec, err := ber.ParseBytes(encodedBytes)
		if err != nil {
			t.Errorf("test %d decoding encoded bytes failed: %s", i, err)
		}
		fromBytes, err := Decode(dec)
		if err != nil {
			t.Errorf("test %d decoding control failed: %s", i, err)
		}
		if !bytes.Equal(encodedBytes, fromBytes.Encode().Bytes()) {
			t.Errorf("test %d round-trip from encoded bytes failed", i)
		}
		if reflect.TypeOf(test) != reflect.TypeOf(fromPacket) {
			t.Errorf("test %d got different type decoding from encoded bytes: %T vs %T", i, fromBytes, test)
		}
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()
	type args struct {
		packet *ber.Packet
	}
	tests := []struct {
		name string
		args args
		exp  Control
		err  bool
	}{
		{
			name: "timeBeforeExpiration", args: args{packet: decodePacket([]byte{0xa0, 0x29, 0x30, 0x27, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0xa, 0x30, 0x8, 0xa0, 0x6, 0x80, 0x4, 0x7f, 0xff, 0xf6, 0x5c})},
			exp: &BeheraPasswordPolicy{Expire: 2147481180, Grace: -1, Error: -1, ErrorString: ""}, err: false,
		},
		{
			name: "graceAuthNsRemaining", args: args{packet: decodePacket([]byte{0xa0, 0x26, 0x30, 0x24, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x7, 0x30, 0x5, 0xa0, 0x3, 0x81, 0x1, 0x11})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: 17, Error: -1, ErrorString: ""}, err: false,
		},
		{
			name: "passwordExpired", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x0})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 0, ErrorString: "Password expired"}, err: false,
		},
		{
			name: "accountLocked", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x1})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 1, ErrorString: "Account locked"}, err: false,
		},
		{
			name: "passwordModNotAllowed", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x3})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 3, ErrorString: "Policy prevents password modification"}, err: false,
		},
		{
			name: "mustSupplyOldPassword", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x4})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 4, ErrorString: "Policy requires old password in order to change password"}, err: false,
		},
		{
			name: "insufficientPasswordQuality", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x5})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 5, ErrorString: "Password fails quality checks"}, err: false,
		},
		{
			name: "passwordTooShort", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x6})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 6, ErrorString: "Password is too short for policy"}, err: false,
		},
		{
			name: "passwordTooYoung", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x7})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 7, ErrorString: "Password has been changed too recently"}, err: false,
		},
		{
			name: "passwordInHistory", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x8})},
			exp: &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 8, ErrorString: "New password is in list of old passwords"}, err: false,
		},
	}
	for i, test := range tests {
		got, err := Decode(tests[i].args.packet.Children[0])
		switch {
		case err == nil && test.err:
			t.Errorf("test %d Decode error = %v, wantErr %t", i, err, test.err)
		case err == nil && !reflect.DeepEqual(got, test.exp):
			t.Errorf("test %d Decode got = %v, want %v", i, got, test.exp)
		}
	}
}

func decodePacket(buf []byte) *ber.Packet {
	p, err := ber.ParseBytes(buf)
	if err != nil {
		panic(err)
	}
	return p
}
