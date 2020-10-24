// Package ber provides encoding and decoding for asn1 ber packets.
package ber

//go:generate stringer -type Tag -trimprefix Tag .
//go:generate stringer -type Class -trimprefix Class .
//go:generate stringer -type Type -trimprefix Type .

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

// Class is the ber packet class enum.
type Class uint8

// Class values.
const (
	ClassUniversal   Class = 0   // 00xxxxxxb
	ClassApplication Class = 64  // 01xxxxxxb
	ClassContext     Class = 128 // 10xxxxxxb
	ClassPrivate     Class = 192 // 11xxxxxxb
)

// Type is the ber packet type enum.
type Type uint8

// Type values.
const (
	TypePrimitive   Type = 0  // xx0xxxxxb
	TypeConstructed Type = 32 // xx1xxxxxb
)

// Tag is the ber packet tag enum.
type Tag uint64

// Tag values.
const (
	TagEOC              Tag = 0x00
	TagBoolean          Tag = 0x01
	TagInteger          Tag = 0x02
	TagBitString        Tag = 0x03
	TagOctetString      Tag = 0x04
	TagNULL             Tag = 0x05
	TagObjectIdentifier Tag = 0x06
	TagObjectDescriptor Tag = 0x07
	TagExternal         Tag = 0x08
	TagRealFloat        Tag = 0x09
	TagEnumerated       Tag = 0x0a
	TagEmbeddedPDV      Tag = 0x0b
	TagUTF8String       Tag = 0x0c
	TagRelativeOID      Tag = 0x0d
	TagSequence         Tag = 0x10
	TagSet              Tag = 0x11
	TagNumericString    Tag = 0x12
	TagPrintableString  Tag = 0x13
	TagT61String        Tag = 0x14
	TagVideotexString   Tag = 0x15
	TagIA5String        Tag = 0x16
	TagUTCTime          Tag = 0x17
	TagGeneralizedTime  Tag = 0x18
	TagGraphicString    Tag = 0x19
	TagVisibleString    Tag = 0x1a
	TagGeneralString    Tag = 0x1b
	TagUniversalString  Tag = 0x1c
	TagCharacterString  Tag = 0x1d
	TagBMPString        Tag = 0x1e

	// tagHigh indicates the start of a high-tag byte sequence.
	tagHigh Tag = 0x1f // xxx11111b

	// tagHighContinueBitmask indicates the high-tag byte sequence should
	// continue.
	tagHighContinueBitmask Tag = 0x80 // 10000000b

	// tagHighValueBitmask obtains the tag value from a high-tag byte sequence
	// byte.
	tagHighValueBitmask Tag = 0x7f // 01111111b
)

// Packet is a ber packet.
type Packet struct {
	Class     Class
	Type      Type
	Tag       Tag
	Value     interface{}
	ByteValue []byte
	Data      *bytes.Buffer
	Children  []*Packet
	Desc      string
}

// ParseLimit reads a ber packet from r up to max bytes.
func ParseLimit(r io.Reader, max int) (int, *Packet, error) {
	n, class, typ, tag, length, err := ParseHeader(r)
	if err != nil {
		return n, nil, err
	}
	p := &Packet{
		Class:    class,
		Type:     typ,
		Tag:      tag,
		Data:     new(bytes.Buffer),
		Children: make([]*Packet, 0, 2),
		Value:    nil,
	}
	if typ == TypeConstructed {
		// TODO: if universal, ensure tag type is allowed to be constructed
		// Track how much content we've read
		total := 0
		for {
			// indefinite length
			if length != -1 {
				// End if we've read what we've been told to
				if total == length {
					break
				}
				// Detect if a packet boundary didn't fall on the expected length
				if total > length {
					return n, nil, ErrPastPacketBoundary
				}
			}
			// Read the next packet
			nn, child, err := ParseLimit(r, max)
			if err != nil {
				return n, nil, err
			}
			total, n = total+nn, n+nn
			// Test is this is the EOC marker for our packet
			if IsEOC(child) {
				// indefinite length
				if length == -1 {
					break
				}
				return n, nil, ErrEOCChildNotAllowedWithDefiniteLength
			}
			// Append and continue
			p.AppendChild(child)
		}
		return n, p, nil
	}
	// indefinite length
	if length == -1 {
		return n, nil, ErrIndefiniteLengthUsedWithPrimitiveType
	}
	// Read definite-length content
	if max > 0 && length > max {
		return n, nil, ErrLengthGreaterThanMax
	}
	buf := make([]byte, length)
	if length > 0 {
		_, err := io.ReadFull(r, buf)
		switch {
		case err != nil && err == io.EOF:
			return n, nil, io.ErrUnexpectedEOF
		case err != nil:
			return n, nil, err
		}
		n += length
	}
	if p.Class == ClassUniversal {
		p.Data.Write(buf)
		p.ByteValue = buf
		switch p.Tag {
		case TagEOC:
		case TagBoolean:
			p.Value, err = ParseBoolean(buf)
		case TagInteger:
			p.Value, _ = ParseInt64(buf)
		case TagBitString:
		case TagOctetString:
			// the actual string encoding is not known here (e.g. for LDAP
			// content is already an UTF8-encoded string). Return the data
			// without modification
			p.Value = string(buf)
		case TagNULL:
		case TagObjectIdentifier:
		case TagObjectDescriptor:
		case TagExternal:
		case TagRealFloat:
			p.Value, err = ParseReal(buf)
		case TagEnumerated:
			p.Value, _ = ParseInt64(buf)
		case TagEmbeddedPDV:
		case TagUTF8String:
			p.Value, err = ParseUTF8String(buf)
		case TagRelativeOID:
		case TagSequence:
		case TagSet:
		case TagNumericString:
		case TagPrintableString:
			p.Value, err = ParsePrintableString(buf)
		case TagT61String:
		case TagVideotexString:
		case TagIA5String:
			p.Value, err = ParseIA5String(buf)
		case TagUTCTime:
		case TagGeneralizedTime:
			p.Value, err = ParseGeneralizedTime(buf)
		case TagGraphicString:
		case TagVisibleString:
		case TagGeneralString:
		case TagUniversalString:
		case TagCharacterString:
		case TagBMPString:
		}
	} else {
		p.Data.Write(buf)
	}
	return n, p, err
}

// Parse parses a ber packet from r.
func Parse(r io.Reader) (int, *Packet, error) {
	return ParseLimit(r, math.MaxInt32)
}

// ParseBytesLimit parses an ber packet from buf, limited to the max
// number of child packets.
func ParseBytesLimit(buf []byte, max int) (*Packet, error) {
	_, p, err := ParseLimit(bytes.NewReader(buf), max)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ParseBytes parses a ber packet from buf.
func ParseBytes(buf []byte) (*Packet, error) {
	return ParseBytesLimit(buf, math.MaxInt32)
}

// NewPacket creates a new ber packet.
func NewPacket(class Class, typ Type, tag Tag, value interface{}, desc string) *Packet {
	p := &Packet{
		Class:    class,
		Type:     typ,
		Tag:      tag,
		Data:     new(bytes.Buffer),
		Children: make([]*Packet, 0, 2),
		Value:    value,
		Desc:     desc,
	}
	if value != nil {
		switch class {
		case ClassUniversal:
			switch tag {
			case TagOctetString:
				v, ok := value.(string)
				if ok {
					p.Data.Write([]byte(v))
				}
			case TagEnumerated:
				v, ok := value.([]byte)
				if ok {
					p.Data.Write(v)
				}
			case TagEmbeddedPDV:
				v, ok := value.([]byte)
				if ok {
					p.Data.Write(v)
				}
			}
		case ClassContext:
			switch tag {
			case TagEnumerated:
				v, ok := value.([]byte)
				if ok {
					p.Data.Write(v)
				}
			case TagEmbeddedPDV:
				v, ok := value.([]byte)
				if ok {
					p.Data.Write(v)
				}
			}
		}
	}
	return p
}

// NewSequence creates a new sequence packet.
func NewSequence(desc string) *Packet {
	return NewPacket(ClassUniversal, TypeConstructed, TagSequence, nil, desc)
}

// NewBoolean creates a new boolean packet.
func NewBoolean(class Class, typ Type, tag Tag, value bool, desc string) *Packet {
	i := int64(0)
	if value {
		i = 1
	}
	p := NewPacket(class, typ, tag, nil, desc)
	p.Value = value
	p.Data.Write(EncodeInt64(i))
	return p
}

// NewLDAPBoolean creates a new RFC 4511-compliant (LDAP) boolean packet.
func NewLDAPBoolean(class Class, typ Type, tag Tag, value bool, desc string) *Packet {
	i := int64(0)
	if value {
		i = 255
	}
	p := NewPacket(class, typ, tag, nil, desc)
	p.Value = value
	p.Data.Write(EncodeInt64(i))
	return p
}

// NewInteger creates a new integer packet.
func NewInteger(class Class, typ Type, tag Tag, value interface{}, desc string) *Packet {
	p := NewPacket(class, typ, tag, nil, desc)
	p.Value = value
	switch v := value.(type) {
	case int:
		p.Data.Write(EncodeInt64(int64(v)))
	case uint:
		p.Data.Write(EncodeInt64(int64(v)))
	case int64:
		p.Data.Write(EncodeInt64(v))
	case uint64:
		// TODO : check range or add encodeUInt...
		p.Data.Write(EncodeInt64(int64(v)))
	case int32:
		p.Data.Write(EncodeInt64(int64(v)))
	case uint32:
		p.Data.Write(EncodeInt64(int64(v)))
	case int16:
		p.Data.Write(EncodeInt64(int64(v)))
	case uint16:
		p.Data.Write(EncodeInt64(int64(v)))
	case int8:
		p.Data.Write(EncodeInt64(int64(v)))
	case uint8:
		p.Data.Write(EncodeInt64(int64(v)))
	default:
		// TODO : add support for big.Int ?
		panic(fmt.Sprintf("Invalid type %T, expected {u|}int{64|32|16|8}", v))
	}
	return p
}

// NewString creates a new string packet.
func NewString(class Class, typ Type, tag Tag, value, desc string) *Packet {
	p := NewPacket(class, typ, tag, nil, desc)
	p.Value = value
	p.Data.Write([]byte(value))
	return p
}

// NewGeneralizedTime creates a new generalized time packet.
func NewGeneralizedTime(class Class, typ Type, tag Tag, value time.Time, desc string) *Packet {
	p := NewPacket(class, typ, tag, nil, desc)
	var s string
	if value.Nanosecond() != 0 {
		s = value.Format(`20060102150405.000000000Z`)
	} else {
		s = value.Format(`20060102150405Z`)
	}
	p.Value = s
	p.Data.Write([]byte(s))
	return p
}

// NewReal creates a new real packet.
func NewReal(class Class, typ Type, tag Tag, value interface{}, desc string) *Packet {
	p := NewPacket(class, typ, tag, nil, desc)
	switch v := value.(type) {
	case float64:
		p.Data.Write(EncodeFloat64(v))
	case float32:
		p.Data.Write(EncodeFloat64(float64(v)))
	default:
		panic(fmt.Sprintf("Invalid type %T, expected float{64|32}", v))
	}
	return p
}

// String satisfies the fmt.Stringer interface.
func (p *Packet) String() string {
	tagStr := fmt.Sprintf("Tag(0x%02X)", p.Tag)
	if p.Class == ClassUniversal {
		tagStr = p.Tag.String()
	}
	return fmt.Sprintf(
		"(Class=%s, Type=%s, Tag=%s, Len=%d, Desc=%q)",
		p.Class,
		p.Type,
		tagStr,
		p.Data.Len(),
		p.Desc,
	)
}

// PrettyPrint pretty-prints the packet to the writer using the specified
// indent.
func (p *Packet) PrettyPrint(w io.Writer, indent int) {
	v := "<nil>"
	if p.Value != nil {
		v = fmt.Sprintf("%q", p.Value)
	}
	_, _ = fmt.Fprintf(
		w,
		"%s%s %s\n",
		strings.Repeat(" ", indent),
		p.String(),
		v,
	)
	for _, child := range p.Children {
		child.PrettyPrint(w, indent+1)
	}
}

// Bytes returns the bytes of the packet.
func (p *Packet) Bytes() []byte {
	buf := new(bytes.Buffer)
	buf.Write(EncodeIdentifier(p.Class, p.Type, p.Tag))
	buf.Write(EncodeLength(p.Data.Len()))
	buf.Write(p.Data.Bytes())
	return buf.Bytes()
}

// AppendChild appends a child to the packet.
func (p *Packet) AppendChild(child *Packet) {
	p.Data.Write(child.Bytes())
	p.Children = append(p.Children, child)
}

// IsEOC determines if the packet is an EOC (end-of-content) packet.
func IsEOC(p *Packet) bool {
	return p != nil &&
		p.Class == ClassUniversal &&
		p.Type == TypePrimitive &&
		p.Tag == TagEOC &&
		len(p.ByteValue) == 0 &&
		len(p.Children) == 0
}
