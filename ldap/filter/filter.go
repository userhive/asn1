package filter

//go:generate stringer -type Filter -trimprefix Filter

import (
	"bytes"
	hexpac "encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/userhive/asn1/ber"
)

// Type values.
const (
	And             ber.Tag = 0
	Or              ber.Tag = 1
	Not             ber.Tag = 2
	EqualityMatch   ber.Tag = 3
	Substrings      ber.Tag = 4
	GreaterOrEqual  ber.Tag = 5
	LessOrEqual     ber.Tag = 6
	Present         ber.Tag = 7
	ApproxMatch     ber.Tag = 8
	ExtensibleMatch ber.Tag = 9
)

// Substring values.
const (
	SubstringsInitial ber.Tag = 0
	SubstringsAny     ber.Tag = 1
	SubstringsFinal   ber.Tag = 2
)

// Rule choices
const (
	RuleMatchingRule ber.Tag = 1
	RuleType         ber.Tag = 2
	RuleMatchValue   ber.Tag = 3
	RuleDNAttributes ber.Tag = 4
)

var any = []byte{'*'}

// Compile converts a string representation of a filter into a BER-encoded packet
func Compile(filter string) (*ber.Packet, error) {
	if len(filter) == 0 || filter[0] != '(' {
		return nil, Error{"filter does not start with an '('"}
	}
	packet, pos, err := compile(filter, 1)
	if err != nil {
		return nil, err
	}
	switch {
	case pos > len(filter):
		return nil, Error{"unexpected end of filter"}
	case pos < len(filter):
		return nil, Errorf("finished compiling filter with extra at end: %s", filter[pos:])
	}
	return packet, nil
}

// Decompile converts a packet representation of a filter into a string representation
func Decompile(packet *ber.Packet) (_ string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = Error{"error decompiling filter"}
		}
	}()
	buf := bytes.NewBuffer(nil)
	buf.WriteByte('(')
	childStr := ""
	switch packet.Tag {
	case And:
		buf.WriteByte('&')
		for _, child := range packet.Children {
			childStr, err = Decompile(child)
			if err != nil {
				return
			}
			buf.WriteString(childStr)
		}
	case Or:
		buf.WriteByte('|')
		for _, child := range packet.Children {
			childStr, err = Decompile(child)
			if err != nil {
				return
			}
			buf.WriteString(childStr)
		}
	case Not:
		buf.WriteByte('!')
		childStr, err = Decompile(packet.Children[0])
		if err != nil {
			return
		}
		buf.WriteString(childStr)
	case Substrings:
		buf.WriteString(string(packet.Children[0].Data.Bytes()))
		buf.WriteByte('=')
		for i, child := range packet.Children[1].Children {
			if i == 0 && child.Tag != SubstringsInitial {
				buf.Write(any)
			}
			buf.WriteString(Escape(string(child.Data.Bytes())))
			if child.Tag != SubstringsFinal {
				buf.Write(any)
			}
		}
	case EqualityMatch:
		buf.WriteString(string(packet.Children[0].Data.Bytes()))
		buf.WriteByte('=')
		buf.WriteString(Escape(string(packet.Children[1].Data.Bytes())))
	case GreaterOrEqual:
		buf.WriteString(string(packet.Children[0].Data.Bytes()))
		buf.WriteString(">=")
		buf.WriteString(Escape(string(packet.Children[1].Data.Bytes())))
	case LessOrEqual:
		buf.WriteString(string(packet.Children[0].Data.Bytes()))
		buf.WriteString("<=")
		buf.WriteString(Escape(string(packet.Children[1].Data.Bytes())))
	case Present:
		buf.WriteString(string(packet.Data.Bytes()))
		buf.WriteString("=*")
	case ApproxMatch:
		buf.WriteString(string(packet.Children[0].Data.Bytes()))
		buf.WriteString("~=")
		buf.WriteString(Escape(string(packet.Children[1].Data.Bytes())))
	case ExtensibleMatch:
		attr := ""
		dnAttributes := false
		matchingRule := ""
		value := ""
		for _, child := range packet.Children {
			switch child.Tag {
			case RuleMatchingRule:
				matchingRule = string(child.Data.Bytes())
			case RuleType:
				attr = string(child.Data.Bytes())
			case RuleMatchValue:
				value = string(child.Data.Bytes())
			case RuleDNAttributes:
				dnAttributes = child.Value.(bool)
			}
		}
		if len(attr) > 0 {
			buf.WriteString(attr)
		}
		if dnAttributes {
			buf.WriteString(":dn")
		}
		if len(matchingRule) > 0 {
			buf.WriteString(":")
			buf.WriteString(matchingRule)
		}
		buf.WriteString(":=")
		buf.WriteString(Escape(value))
	}
	buf.WriteByte(')')
	return buf.String(), nil
}

func compileSet(filter string, pos int, parent *ber.Packet) (int, error) {
	for pos < len(filter) && filter[pos] == '(' {
		child, newPos, err := compile(filter, pos+1)
		if err != nil {
			return pos, err
		}
		pos = newPos
		parent.AppendChild(child)
	}
	if pos == len(filter) {
		return pos, Error{"unexpected end of filter"}
	}

	return pos + 1, nil
}

func compile(filter string, pos int) (*ber.Packet, int, error) {
	var (
		packet *ber.Packet
		err    error
	)
	defer func() {
		if r := recover(); r != nil {
			err = Error{"error compiling filter"}
		}
	}()
	newPos := pos
	currentRune, currentWidth := utf8.DecodeRuneInString(filter[newPos:])
	switch currentRune {
	case utf8.RuneError:
		return nil, 0, Errorf("error reading rune at position %d", newPos)
	case '(':
		packet, newPos, err = compile(filter, pos+currentWidth)
		newPos++
		return packet, newPos, err
	case '&':
		packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, And, nil, And.String())
		newPos, err = compileSet(filter, pos+currentWidth, packet)
		return packet, newPos, err
	case '|':
		packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, Or, nil, Or.String())
		newPos, err = compileSet(filter, pos+currentWidth, packet)
		return packet, newPos, err
	case '!':
		packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, Not, nil, Not.String())
		var child *ber.Packet
		child, newPos, err = compile(filter, pos+currentWidth)
		packet.AppendChild(child)
		return packet, newPos, err
	default:
		const (
			stateReadingAttr                   = 0
			stateReadingExtensibleMatchingRule = 1
			stateReadingCondition              = 2
		)
		state := stateReadingAttr
		attribute := bytes.NewBuffer(nil)
		extensibleDNAttributes := false
		extensibleMatchingRule := bytes.NewBuffer(nil)
		condition := bytes.NewBuffer(nil)
		for newPos < len(filter) {
			remaining := filter[newPos:]
			currentRune, currentWidth = utf8.DecodeRuneInString(remaining)
			if currentRune == ')' {
				break
			}
			if currentRune == utf8.RuneError {
				return packet, newPos, Errorf("error reading rune at position %d", newPos)
			}

			switch state {
			case stateReadingAttr:
				switch {
				// Extensible rule, with only DN-matching
				case currentRune == ':' && strings.HasPrefix(remaining, ":dn:="):
					packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, ExtensibleMatch, nil, ExtensibleMatch.String())
					extensibleDNAttributes = true
					state = stateReadingCondition
					newPos += 5

				// Extensible rule, with DN-matching and a matching OID
				case currentRune == ':' && strings.HasPrefix(remaining, ":dn:"):
					packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, ExtensibleMatch, nil, ExtensibleMatch.String())
					extensibleDNAttributes = true
					state = stateReadingExtensibleMatchingRule
					newPos += 4

				// Extensible rule, with attr only
				case currentRune == ':' && strings.HasPrefix(remaining, ":="):
					packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, ExtensibleMatch, nil, ExtensibleMatch.String())
					state = stateReadingCondition
					newPos += 2

				// Extensible rule, with no DN attribute matching
				case currentRune == ':':
					packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, ExtensibleMatch, nil, ExtensibleMatch.String())
					state = stateReadingExtensibleMatchingRule
					newPos++

				// Equality condition
				case currentRune == '=':
					packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, EqualityMatch, nil, EqualityMatch.String())
					state = stateReadingCondition
					newPos++

				// Greater-than or equal
				case currentRune == '>' && strings.HasPrefix(remaining, ">="):
					packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, GreaterOrEqual, nil, GreaterOrEqual.String())
					state = stateReadingCondition
					newPos += 2

				// Less-than or equal
				case currentRune == '<' && strings.HasPrefix(remaining, "<="):
					packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, LessOrEqual, nil, LessOrEqual.String())
					state = stateReadingCondition
					newPos += 2

				// Approx
				case currentRune == '~' && strings.HasPrefix(remaining, "~="):
					packet = ber.NewPacket(ber.ClassContext, ber.TypeConstructed, ApproxMatch, nil, ApproxMatch.String())
					state = stateReadingCondition
					newPos += 2

				// Still reading the attribute name
				default:
					attribute.WriteRune(currentRune)
					newPos += currentWidth
				}

			case stateReadingExtensibleMatchingRule:
				switch {

				// Matching rule OID is done
				case currentRune == ':' && strings.HasPrefix(remaining, ":="):
					state = stateReadingCondition
					newPos += 2

				// Still reading the matching rule oid
				default:
					extensibleMatchingRule.WriteRune(currentRune)
					newPos += currentWidth
				}

			case stateReadingCondition:
				// append to the condition
				condition.WriteRune(currentRune)
				newPos += currentWidth
			}
		}

		if newPos == len(filter) {
			return packet, newPos, Error{"unexpected end of filter"}
		}
		if packet == nil {
			return packet, newPos, Error{"error parsing filter"}
		}

		switch {
		case packet.Tag == ExtensibleMatch:
			// Rule ::= SEQUENCE {
			//         matchingRule    [1] MatchingRuleID OPTIONAL,
			//         type            [2] AttributeDescription OPTIONAL,
			//         matchValue      [3] AssertionValue,
			//         dnAttributes    [4] BOOLEAN DEFAULT FALSE
			// }

			// Include the matching rule oid, if specified
			if extensibleMatchingRule.Len() > 0 {
				packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, RuleMatchingRule, extensibleMatchingRule.String(), RuleMatchingRule.String()))
			}

			// Include the attribute, if specified
			if attribute.Len() > 0 {
				packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, RuleType, attribute.String(), RuleType.String()))
			}

			// Add the value (only required child)
			encodedString, encodeErr := Unescape(condition.Bytes())
			if encodeErr != nil {
				return packet, newPos, encodeErr
			}
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, RuleMatchValue, encodedString, RuleMatchValue.String()))

			// Defaults to false, so only include in the sequence if true
			if extensibleDNAttributes {
				packet.AppendChild(ber.NewBoolean(ber.ClassContext, ber.TypePrimitive, RuleDNAttributes, extensibleDNAttributes, RuleDNAttributes.String()))
			}

		case packet.Tag == EqualityMatch && bytes.Equal(condition.Bytes(), any):
			packet = ber.NewString(ber.ClassContext, ber.TypePrimitive, Present, attribute.String(), Present.String())
		case packet.Tag == EqualityMatch && bytes.Index(condition.Bytes(), any) > -1:
			packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute.String(), "Attribute"))
			packet.Tag = Substrings
			packet.Desc = packet.Tag.String()
			seq := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
			parts := bytes.Split(condition.Bytes(), any)
			for i, part := range parts {
				if len(part) == 0 {
					continue
				}
				var tag ber.Tag
				switch i {
				case 0:
					tag = SubstringsInitial
				case len(parts) - 1:
					tag = SubstringsFinal
				default:
					tag = SubstringsAny
				}
				encodedString, encodeErr := Unescape(part)
				if encodeErr != nil {
					return packet, newPos, encodeErr
				}
				seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tag, encodedString, tag.String()))
			}
			packet.AppendChild(seq)
		default:
			encodedString, encodeErr := Unescape(condition.Bytes())
			if encodeErr != nil {
				return packet, newPos, encodeErr
			}
			packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute.String(), "Attribute"))
			packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, encodedString, "Condition"))
		}
		newPos += currentWidth
		return packet, newPos, err
	}
}

// Unescapes converts from "ABC\xx\xx\xx" form to literal bytes for
// transport.
func Unescape(src []byte) (string, error) {
	var (
		buffer  bytes.Buffer
		offset  int
		reader  = bytes.NewReader(src)
		byteHex []byte
		byteVal []byte
	)
	for {
		runeVal, runeSize, err := reader.ReadRune()
		if err == io.EOF {
			return buffer.String(), nil
		} else if err != nil {
			return "", Errorf("failed to read filter: %v", err)
		} else if runeVal == unicode.ReplacementChar {
			return "", Errorf("error reading rune at position %d", offset)
		}
		if runeVal == '\\' {
			// http://tools.ietf.org/search/rfc4515
			// \ (%x5C) is not a valid character unless it is followed by two HEX characters due to not
			// being a member of UTF1SUBSET.
			if byteHex == nil {
				byteHex = make([]byte, 2)
				byteVal = make([]byte, 1)
			}
			if _, err := io.ReadFull(reader, byteHex); err != nil {
				if err == io.ErrUnexpectedEOF {
					return "", Error{"missing characters for escape in filter"}
				}
				return "", Errorf("invalid characters for escape in filter: %v", err)
			}
			if _, err := hexpac.Decode(byteVal, byteHex); err != nil {
				return "", Errorf("invalid characters for escape in filter: %v", err)
			}
			buffer.Write(byteVal)
		} else {
			buffer.WriteRune(runeVal)
		}
		offset += runeSize
	}
}

// Escape escapes special characters `()*\` and those not in the range 0 < c <
// 0x80 in filter.
func Escape(filter string) string {
	escape := 0
	for i := 0; i < len(filter); i++ {
		if mustEscape(filter[i]) {
			escape++
		}
	}
	if escape == 0 {
		return filter
	}
	buf := make([]byte, len(filter)+escape*2)
	for i, j := 0, 0; i < len(filter); i++ {
		c := filter[i]
		if mustEscape(c) {
			buf[j+0] = '\\'
			buf[j+1] = hex[c>>4]
			buf[j+2] = hex[c&0xf]
			j += 3
		} else {
			buf[j] = c
			j++
		}
	}
	return string(buf)
}

var hex = "0123456789abcdef"

func mustEscape(c byte) bool {
	return c > 0x7f || c == '(' || c == ')' || c == '\\' || c == '*' || c == 0
}

type Error struct {
	Msg string
}

func (err Error) Error() string {
	return err.Msg
}

func Errorf(s string, v ...interface{}) error {
	return Error{fmt.Sprintf(s, v...)}
}