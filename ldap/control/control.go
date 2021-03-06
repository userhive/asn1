package control

import (
	"fmt"
	"strconv"

	"github.com/userhive/asn1/ber"
)

// Control defines an interface controls provide to encode and describe themselves
type Control interface {
	// GetControl returns the Control
	GetControl() string
	// Encode returns the ber packet representation
	Encode() *ber.Packet
	// String returns a human-readable description
	String() string
}

type ControlID string

func (c ControlID) String() string {
	return string(c)
}

const (
	ControlPaging                      ControlID = "1.2.840.113556.1.4.319"    // https://www.ietf.org/rfc/rfc2696.txt
	ControlBeheraPasswordPolicy        ControlID = "1.3.6.1.4.1.42.2.27.8.5.1" // https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
	ControlVChuPasswordMustChange      ControlID = "2.16.840.1.113730.3.4.4"   // https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlVChuPasswordWarning         ControlID = "2.16.840.1.113730.3.4.5"   // https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlManageDsaIT                 ControlID = "2.16.840.1.113730.3.4.2"   // https://tools.ietf.org/html/rfc3296
	ControlMicrosoftChangeNotification ControlID = "1.2.840.113556.1.4.528"    // https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
	ControlMicrosoftShowDeletedObjects ControlID = "1.2.840.113556.1.4.417"    // https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
)

// Encode
func Encode(controls ...Control) *ber.Packet {
	p := ber.NewPacket(
		ber.ClassContext,
		ber.TypeConstructed,
		0,
		nil,
	)
	for _, c := range controls {
		if c == nil {
			panic("passed control is nil")
		}
		p.AppendChild(c.Encode())
	}
	return p
}

// Decode returns a control read from the given packet, or nil if no recognized control can be made
func Decode(p *ber.Packet) (Control, error) {
	var controlType ControlID
	var Criticality bool
	var value *ber.Packet
	switch len(p.Children) {
	case 0:
		// at least one child is required for control type
		return nil, fmt.Errorf("at least one child is required for control type")
	case 1:
		// just type, no criticality or value
		controlType = ControlID(p.Children[0].Value.(string))
	case 2:
		controlType = ControlID(p.Children[0].Value.(string))
		// Children[1] could be criticality or value (both are optional)
		// duck-type on whether this is a boolean
		if _, ok := p.Children[1].Value.(bool); ok {
			Criticality = p.Children[1].Value.(bool)
		} else {
			value = p.Children[1]
		}
	case 3:
		controlType = ControlID(p.Children[0].Value.(string))
		Criticality = p.Children[1].Value.(bool)
		value = p.Children[2]
	default:
		// more than 3 children is invalid
		return nil, fmt.Errorf("more than 3 children is invalid for controls")
	}
	switch controlType {
	case ControlManageDsaIT:
		return NewManageDsaIT(Criticality), nil
	case ControlPaging:
		c := new(Paging)
		if value.Value != nil {
			valueChildren, err := ber.ParseBytes(value.Data.Bytes())
			if err != nil {
				return nil, fmt.Errorf("failed to decode data bytes: %s", err)
			}
			value.Data.Truncate(0)
			value.Value = nil
			value.AppendChild(valueChildren)
		}
		value = value.Children[0]
		c.PagingSize = uint32(value.Children[0].Value.(int64))
		c.Cookie = value.Children[1].Data.Bytes()
		value.Children[1].Value = c.Cookie
		return c, nil
	case ControlBeheraPasswordPolicy:
		c := NewBeheraPasswordPolicy()
		if value.Value != nil {
			valueChildren, err := ber.ParseBytes(value.Data.Bytes())
			if err != nil {
				return nil, fmt.Errorf("failed to decode data bytes: %s", err)
			}
			value.Data.Truncate(0)
			value.Value = nil
			value.AppendChild(valueChildren)
		}
		sequence := value.Children[0]
		for _, child := range sequence.Children {
			if child.Tag == 0 {
				// Warning
				warningPacket := child.Children[0]
				val, err := ber.ParseInt64(warningPacket.Data.Bytes())
				if err != nil {
					return nil, fmt.Errorf("failed to decode data bytes: %s", err)
				}
				if warningPacket.Tag == 0 {
					// timeBeforeExpiration
					c.Expire = val
					warningPacket.Value = c.Expire
				} else if warningPacket.Tag == 1 {
					// graceAuthNsRemaining
					c.Grace = val
					warningPacket.Value = c.Grace
				}
			} else if child.Tag == 1 {
				// Error
				bs := child.Data.Bytes()
				if len(bs) != 1 || bs[0] > 8 {
					return nil, fmt.Errorf("failed to decode data bytes: %s", "invalid PasswordPolicyResponse enum value")
				}
				val := int8(bs[0])
				c.Error = val
				child.Value = c.Error
				c.ErrorString = BeheraPasswordPolicyErrorMap[Behera(c.Error)]
			}
		}
		return c, nil
	case ControlVChuPasswordMustChange:
		c := &VChuPasswordMustChange{MustChange: true}
		return c, nil
	case ControlVChuPasswordWarning:
		c := &VChuPasswordWarning{Expire: -1}
		expire, err := strconv.ParseInt(value.Data.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value as int: %s", err)
		}
		c.Expire = expire
		value.Value = c.Expire
		return c, nil
	case ControlMicrosoftChangeNotification:
		return NewMicrosoftChangeNotification(), nil
	case ControlMicrosoftShowDeletedObjects:
		return NewMicrosoftShowDeletedObjects(), nil
	default:
		c := new(String)
		c.OID = controlType.String()
		c.Criticality = Criticality
		if value != nil {
			c.ControlValue = value.Value.(string)
		}
		return c, nil
	}
}

// String implements the Control interface for simple controls
type String struct {
	OID          string
	Criticality  bool
	ControlValue string
}

// NewString returns a generic control
func NewString(typ string, criticality bool, controlValue string) *String {
	return &String{
		OID:          typ,
		Criticality:  criticality,
		ControlValue: controlValue,
	}
}

// GetControl returns the OID
func (c *String) GetControl() string {
	return c.OID
}

// Encode returns the ber packet representation
func (c *String) Encode() *ber.Packet {
	p := ber.NewPacket(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
	)
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			c.OID,
		),
	)
	if c.Criticality {
		p.AppendChild(
			ber.NewBoolean(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagBoolean,
				c.Criticality,
			),
		)
	}
	if c.ControlValue != "" {
		p.AppendChild(
			ber.NewString(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagOctetString,
				string(c.ControlValue),
			),
		)
	}
	return p
}

// String returns a human-readable description
func (c *String) String() string {
	return fmt.Sprintf(
		"Control OID: %s Criticality: %t Control Value: %s",
		c.OID,
		c.Criticality,
		c.ControlValue,
	)
}

// Paging implements the paging control described in https://www.ietf.org/rfc/rfc2696.txt
type Paging struct {
	// PagingSize indicates the page size
	PagingSize uint32
	// Cookie is an opaque value returned by the server to track a paging cursor
	Cookie []byte
}

// NewPaging returns a paging control
func NewPaging(pagingSize uint32) *Paging {
	return &Paging{PagingSize: pagingSize}
}

// GetControl returns the OID
func (c *Paging) GetControl() string {
	return ControlPaging.String()
}

// Encode returns the ber packet representation
func (c *Paging) Encode() *ber.Packet {
	p := ber.NewPacket(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
	)
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			ControlPaging.String(),
		),
	)
	p2 := ber.NewPacket(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
	)
	seq := ber.NewPacket(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
	)
	seq.AppendChild(
		ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			int64(c.PagingSize),
		),
	)
	cookie := ber.NewPacket(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
	)
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)
	p.AppendChild(p2)
	return p
}

// String returns a human-readable description
func (c *Paging) String() string {
	return fmt.Sprintf(
		"Control OID: %s Criticality: %t  PagingSize: %d  Cookie: %q",
		ControlPaging,
		false,
		c.PagingSize,
		c.Cookie,
	)
}

// SetCookie stores the given cookie in the paging control
func (c *Paging) SetCookie(cookie []byte) {
	c.Cookie = cookie
}

// ManageDsaIT implements the control described in https://tools.ietf.org/html/rfc3296
type ManageDsaIT struct {
	// Criticality indicates if this control is required
	Criticality bool
}

// GetControl returns the OID
func (c *ManageDsaIT) GetControl() string {
	return ControlManageDsaIT.String()
}

// Encode returns the ber packet representation
func (c *ManageDsaIT) Encode() *ber.Packet {
	// FIXME
	p := ber.NewPacket(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
	)
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			ControlManageDsaIT.String(),
		),
	)
	if c.Criticality {
		p.AppendChild(
			ber.NewBoolean(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagBoolean,
				c.Criticality,
			),
		)
	}
	return p
}

// String returns a human-readable description
func (c *ManageDsaIT) String() string {
	return fmt.Sprintf(
		"Control OID: %s Criticality: %t",
		ControlManageDsaIT,
		c.Criticality,
	)
}

// NewManageDsaIT returns a ControlManageDsaIT control
func NewManageDsaIT(Criticality bool) *ManageDsaIT {
	return &ManageDsaIT{Criticality: Criticality}
}
