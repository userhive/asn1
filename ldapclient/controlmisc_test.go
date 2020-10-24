package ldapclient

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldap/control"
)

func TestPaging(t *testing.T) {
	t.Parallel()
	runControlTest(t, control.NewPaging(0))
	runControlTest(t, control.NewPaging(100))
}

func TestControlManageDsaIT(t *testing.T) {
	t.Parallel()
	runControlTest(t, control.NewManageDsaIT(true))
	runControlTest(t, control.NewManageDsaIT(false))
}

func TestControlMicrosoftNotification(t *testing.T) {
	t.Parallel()
	runControlTest(t, control.NewMicrosoftNotification())
}

func TestControlMicrosoftShowDeleted(t *testing.T) {
	t.Parallel()
	runControlTest(t, control.NewMicrosoftShowDeleted())
}

func TestControlString(t *testing.T) {
	t.Parallel()
	runControlTest(t, control.NewString("x", true, "y"))
	runControlTest(t, control.NewString("x", true, ""))
	runControlTest(t, control.NewString("x", false, "y"))
	runControlTest(t, control.NewString("x", false, ""))
}

func runControlTest(t *testing.T, originalControl control.Control) {
	header := ""
	if callerpc, _, line, ok := runtime.Caller(1); ok {
		if caller := runtime.FuncForPC(callerpc); caller != nil {
			header = fmt.Sprintf("%s:%d: ", caller.Name(), line)
		}
	}
	encodedPacket := originalControl.Encode()
	encodedBytes := encodedPacket.Bytes()
	// Decode directly from the encoded packet (ensures Value is correct)
	fromPacket, err := control.Decode(encodedPacket)
	if err != nil {
		t.Errorf("%sdecoding encoded bytes control failed: %s", header, err)
	}
	if !bytes.Equal(encodedBytes, fromPacket.Encode().Bytes()) {
		t.Errorf("%sround-trip from encoded packet failed", header)
	}
	if reflect.TypeOf(originalControl) != reflect.TypeOf(fromPacket) {
		t.Errorf("%sgot different type decoding from encoded packet: %T vs %T", header, fromPacket, originalControl)
	}
	// Decode from the wire bytes (ensures ber-encoding is correct)
	pkt, err := ber.ParseBytes(encodedBytes)
	if err != nil {
		t.Errorf("%sdecoding encoded bytes failed: %s", header, err)
	}
	fromBytes, err := control.Decode(pkt)
	if err != nil {
		t.Errorf("%sdecoding control failed: %s", header, err)
	}
	if !bytes.Equal(encodedBytes, fromBytes.Encode().Bytes()) {
		t.Errorf("%sround-trip from encoded bytes failed", header)
	}
	if reflect.TypeOf(originalControl) != reflect.TypeOf(fromPacket) {
		t.Errorf("%sgot different type decoding from encoded bytes: %T vs %T", header, fromBytes, originalControl)
	}
}

func TestDescribeControlManageDsaIT(t *testing.T) {
	t.Parallel()
	runAddControlDescriptions(t, control.NewManageDsaIT(false), "Control Type (Manage DSA IT)")
	runAddControlDescriptions(t, control.NewManageDsaIT(true), "Control Type (Manage DSA IT)", "Criticality")
}

func TestDescribePaging(t *testing.T) {
	t.Parallel()
	runAddControlDescriptions(t, control.NewPaging(100), "Control Type (Paging)", "Control Value (Paging)")
	runAddControlDescriptions(t, control.NewPaging(0), "Control Type (Paging)", "Control Value (Paging)")
}

func TestDescribeControlMicrosoftNotification(t *testing.T) {
	t.Parallel()
	runAddControlDescriptions(t, control.NewMicrosoftNotification(), "Control Type (Change Notification - Microsoft)")
}

func TestDescribeControlMicrosoftShowDeleted(t *testing.T) {
	t.Parallel()
	runAddControlDescriptions(t, control.NewMicrosoftShowDeleted(), "Control Type (Show Deleted Objects - Microsoft)")
}

func TestDescribeControlString(t *testing.T) {
	t.Parallel()
	runAddControlDescriptions(t, control.NewString("x", true, "y"), "Control Type ()", "Criticality", "Control Value")
	runAddControlDescriptions(t, control.NewString("x", true, ""), "Control Type ()", "Criticality")
	runAddControlDescriptions(t, control.NewString("x", false, "y"), "Control Type ()", "Control Value")
	runAddControlDescriptions(t, control.NewString("x", false, ""), "Control Type ()")
}

func runAddControlDescriptions(t *testing.T, originalControl control.Control, childDescriptions ...string) {
	header := ""
	if callerpc, _, line, ok := runtime.Caller(1); ok {
		if caller := runtime.FuncForPC(callerpc); caller != nil {
			header = fmt.Sprintf("%s:%d: ", caller.Name(), line)
		}
	}
	encodedControls := control.Encode(control.Control(originalControl))
	AddControlDescriptions(encodedControls)
	encodedPacket := encodedControls.Children[0]
	if len(encodedPacket.Children) != len(childDescriptions) {
		t.Errorf("%sinvalid number of children: %d != %d", header, len(encodedPacket.Children), len(childDescriptions))
	}
	for i, desc := range childDescriptions {
		if encodedPacket.Children[i].Desc != desc {
			t.Errorf("%sdescription not as expected: %s != %s", header, encodedPacket.Children[i].Desc, desc)
		}
	}
}

func TestDecodeControl(t *testing.T) {
	t.Parallel()
	type args struct {
		packet *ber.Packet
	}
	tests := []struct {
		name    string
		args    args
		want    control.Control
		wantErr bool
	}{
		{
			name: "timeBeforeExpiration", args: args{packet: decodePacket([]byte{0xa0, 0x29, 0x30, 0x27, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0xa, 0x30, 0x8, 0xa0, 0x6, 0x80, 0x4, 0x7f, 0xff, 0xf6, 0x5c})},
			want: &control.BeheraPasswordPolicy{Expire: 2147481180, Grace: -1, Error: -1, ErrorString: ""}, wantErr: false,
		},
		{
			name: "graceAuthNsRemaining", args: args{packet: decodePacket([]byte{0xa0, 0x26, 0x30, 0x24, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x7, 0x30, 0x5, 0xa0, 0x3, 0x81, 0x1, 0x11})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: 17, Error: -1, ErrorString: ""}, wantErr: false,
		},
		{
			name: "passwordExpired", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x0})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 0, ErrorString: "Password expired"}, wantErr: false,
		},
		{
			name: "accountLocked", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x1})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 1, ErrorString: "Account locked"}, wantErr: false,
		},
		{
			name: "passwordModNotAllowed", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x3})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 3, ErrorString: "Policy prevents password modification"}, wantErr: false,
		},
		{
			name: "mustSupplyOldPassword", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x4})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 4, ErrorString: "Policy requires old password in order to change password"}, wantErr: false,
		},
		{
			name: "insufficientPasswordQuality", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x5})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 5, ErrorString: "Password fails quality checks"}, wantErr: false,
		},
		{
			name: "passwordTooShort", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x6})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 6, ErrorString: "Password is too short for policy"}, wantErr: false,
		},
		{
			name: "passwordTooYoung", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x7})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 7, ErrorString: "Password has been changed too recently"}, wantErr: false,
		},
		{
			name: "passwordInHistory", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x8})},
			want: &control.BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 8, ErrorString: "New password is in list of old passwords"}, wantErr: false,
		},
	}
	for i := range tests {
		err := AddControlDescriptions(tests[i].args.packet)
		if err != nil {
			t.Fatal(err)
		}
		tests[i].args.packet = tests[i].args.packet.Children[0]
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := control.Decode(test.args.packet)
			if (err != nil) != test.wantErr {
				t.Errorf("DecodeControl() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("DecodeControl() got = %v, want %v", got, test.want)
			}
		})
	}
}

func decodePacket(buf []byte) *ber.Packet {
	p, err := ber.ParseBytes(buf)
	if err != nil {
		panic(err)
	}
	return p
}

func TestAddControlDescriptions(t *testing.T) {
	type args struct {
		packet *ber.Packet
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "timeBeforeExpiration", args: args{packet: decodePacket([]byte{0xa0, 0x29, 0x30, 0x27, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0xa, 0x30, 0x8, 0xa0, 0x6, 0x80, 0x4, 0x7f, 0xff, 0xf6, 0x5c})}, wantErr: false},
		{name: "graceAuthNsRemaining", args: args{packet: decodePacket([]byte{0xa0, 0x26, 0x30, 0x24, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x7, 0x30, 0x5, 0xa0, 0x3, 0x81, 0x1, 0x11})}, wantErr: false},
		{name: "passwordExpired", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x0})}, wantErr: false},
		{name: "accountLocked", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x1})}, wantErr: false},
		{name: "passwordModNotAllowed", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x3})}, wantErr: false},
		{name: "mustSupplyOldPassword", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x4})}, wantErr: false},
		{name: "insufficientPasswordQuality", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x5})}, wantErr: false},
		{name: "passwordTooShort", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x6})}, wantErr: false},
		{name: "passwordTooYoung", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x7})}, wantErr: false},
		{name: "passwordInHistory", args: args{packet: decodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x8})}, wantErr: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := AddControlDescriptions(test.args.packet); (err != nil) != test.wantErr {
				t.Errorf("addControlDescriptions() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
