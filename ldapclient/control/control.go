package control

import (
	"fmt"
	"strconv"

	"github.com/userhive/asn1/ber"
)

const (
	// OIDPaging - https://www.ietf.org/rfc/rfc2696.txt
	OIDPaging = "1.2.840.113556.1.4.319"
	// OIDBeheraPasswordPolicy - https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
	OIDBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"
	// OIDVChuPasswordMustChange - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	OIDVChuPasswordMustChange = "2.16.840.1.113730.3.4.4"
	// OIDVChuPasswordWarning - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	OIDVChuPasswordWarning = "2.16.840.1.113730.3.4.5"
	// OIDManageDsaIT - https://tools.ietf.org/html/rfc3296
	OIDManageDsaIT = "2.16.840.1.113730.3.4.2"
	// OIDMicrosoftNotification - https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
	OIDMicrosoftNotification = "1.2.840.113556.1.4.528"
	// OIDMicrosoftShowDeleted - https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
	OIDMicrosoftShowDeleted = "1.2.840.113556.1.4.417"
)

// OIDMap maps controls to text descriptions
var OIDMap = map[string]string{
	OIDPaging:                "Paging",
	OIDBeheraPasswordPolicy:  "Password Policy - Behera Draft",
	OIDManageDsaIT:           "Manage DSA IT",
	OIDMicrosoftNotification: "Change Notification - Microsoft",
	OIDMicrosoftShowDeleted:  "Show Deleted Objects - Microsoft",
}

// Control defines an interface controls provide to encode and describe themselves
type Control interface {
	// GetOID returns the OID
	GetOID() string
	// Encode returns the ber packet representation
	Encode() *ber.Packet
	// String returns a human-readable description
	String() string
}

// ControlString implements the Control interface for simple controls
type ControlString struct {
	OID          string
	Criticality  bool
	ControlValue string
}

// GetOID returns the OID
func (c *ControlString) GetOID() string {
	return c.OID
}

// Encode returns the ber packet representation
func (c *ControlString) Encode() *ber.Packet {
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.OID, "Control OID ("+OIDMap[c.OID]+")"))
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	if c.ControlValue != "" {
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(c.ControlValue), "Control Value"))
	}
	return packet
}

// String returns a human-readable description
func (c *ControlString) String() string {
	return fmt.Sprintf("Control OID: %s (%q)  Criticality: %t  Control Value: %s", OIDMap[c.OID], c.OID, c.Criticality, c.ControlValue)
}

// ControlPaging implements the paging control described in https://www.ietf.org/rfc/rfc2696.txt
type ControlPaging struct {
	// PagingSize indicates the page size
	PagingSize uint32
	// Cookie is an opaque value returned by the server to track a paging cursor
	Cookie []byte
}

// GetOID returns the OID
func (c *ControlPaging) GetOID() string {
	return OIDPaging
}

// Encode returns the ber packet representation
func (c *ControlPaging) Encode() *ber.Packet {
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDPaging, "Control OID ("+OIDMap[OIDPaging]+")"))
	p2 := ber.NewPacket(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.PagingSize), "Paging Size"))
	cookie := ber.NewPacket(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)
	packet.AppendChild(p2)
	return packet
}

// String returns a human-readable description
func (c *ControlPaging) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)  Criticality: %t  PagingSize: %d  Cookie: %q",
		OIDMap[OIDPaging],
		OIDPaging,
		false,
		c.PagingSize,
		c.Cookie)
}

// SetCookie stores the given cookie in the paging control
func (c *ControlPaging) SetCookie(cookie []byte) {
	c.Cookie = cookie
}

// ControlBeheraPasswordPolicy implements the control described in https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
type ControlBeheraPasswordPolicy struct {
	// Expire contains the number of seconds before a password will expire
	Expire int64
	// Grace indicates the remaining number of times a user will be allowed to authenticate with an expired password
	Grace int64
	// Error indicates the error code
	Error int8
	// ErrorString is a human readable error
	ErrorString string
}

// GetOID returns the OID
func (c *ControlBeheraPasswordPolicy) GetOID() string {
	return OIDBeheraPasswordPolicy
}

// Encode returns the ber packet representation
func (c *ControlBeheraPasswordPolicy) Encode() *ber.Packet {
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDBeheraPasswordPolicy, "Control OID ("+OIDMap[OIDBeheraPasswordPolicy]+")"))
	return packet
}

// String returns a human-readable description
func (c *ControlBeheraPasswordPolicy) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)  Criticality: %t  Expire: %d  Grace: %d  Error: %d, ErrorString: %s",
		OIDMap[OIDBeheraPasswordPolicy],
		OIDBeheraPasswordPolicy,
		false,
		c.Expire,
		c.Grace,
		c.Error,
		c.ErrorString)
}

// ControlVChuPasswordMustChange implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type ControlVChuPasswordMustChange struct {
	// MustChange indicates if the password is required to be changed
	MustChange bool
}

// GetOID returns the OID
func (c *ControlVChuPasswordMustChange) GetOID() string {
	return OIDVChuPasswordMustChange
}

// Encode returns the ber packet representation
func (c *ControlVChuPasswordMustChange) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *ControlVChuPasswordMustChange) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)  Criticality: %t  MustChange: %v",
		OIDMap[OIDVChuPasswordMustChange],
		OIDVChuPasswordMustChange,
		false,
		c.MustChange)
}

// ControlVChuPasswordWarning implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type ControlVChuPasswordWarning struct {
	// Expire indicates the time in seconds until the password expires
	Expire int64
}

// GetOID returns the OID
func (c *ControlVChuPasswordWarning) GetOID() string {
	return OIDVChuPasswordWarning
}

// Encode returns the ber packet representation
func (c *ControlVChuPasswordWarning) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *ControlVChuPasswordWarning) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)  Criticality: %t  Expire: %b",
		OIDMap[OIDVChuPasswordWarning],
		OIDVChuPasswordWarning,
		false,
		c.Expire)
}

// ControlManageDsaIT implements the control described in https://tools.ietf.org/html/rfc3296
type ControlManageDsaIT struct {
	// Criticality indicates if this control is required
	Criticality bool
}

// GetOID returns the OID
func (c *ControlManageDsaIT) GetOID() string {
	return OIDManageDsaIT
}

// Encode returns the ber packet representation
func (c *ControlManageDsaIT) Encode() *ber.Packet {
	// FIXME
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDManageDsaIT, "Control OID ("+OIDMap[OIDManageDsaIT]+")"))
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	return packet
}

// String returns a human-readable description
func (c *ControlManageDsaIT) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)  Criticality: %t",
		OIDMap[OIDManageDsaIT],
		OIDManageDsaIT,
		c.Criticality)
}

// NewControlManageDsaIT returns a ControlManageDsaIT control
func NewControlManageDsaIT(Criticality bool) *ControlManageDsaIT {
	return &ControlManageDsaIT{Criticality: Criticality}
}

// ControlMicrosoftNotification implements the control described in https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
type ControlMicrosoftNotification struct{}

// GetOID returns the OID
func (c *ControlMicrosoftNotification) GetOID() string {
	return OIDMicrosoftNotification
}

// Encode returns the ber packet representation
func (c *ControlMicrosoftNotification) Encode() *ber.Packet {
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDMicrosoftNotification, "Control OID ("+OIDMap[OIDMicrosoftNotification]+")"))
	return packet
}

// String returns a human-readable description
func (c *ControlMicrosoftNotification) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)",
		OIDMap[OIDMicrosoftNotification],
		OIDMicrosoftNotification)
}

// NewControlMicrosoftNotification returns a ControlMicrosoftNotification control
func NewControlMicrosoftNotification() *ControlMicrosoftNotification {
	return &ControlMicrosoftNotification{}
}

// ControlMicrosoftShowDeleted implements the control described in https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
type ControlMicrosoftShowDeleted struct{}

// GetOID returns the OID
func (c *ControlMicrosoftShowDeleted) GetOID() string {
	return OIDMicrosoftShowDeleted
}

// Encode returns the ber packet representation
func (c *ControlMicrosoftShowDeleted) Encode() *ber.Packet {
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDMicrosoftShowDeleted, "Control OID ("+OIDMap[OIDMicrosoftShowDeleted]+")"))
	return packet
}

// String returns a human-readable description
func (c *ControlMicrosoftShowDeleted) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)",
		OIDMap[OIDMicrosoftShowDeleted],
		OIDMicrosoftShowDeleted)
}

// NewControlMicrosoftShowDeleted returns a ControlMicrosoftShowDeleted control
func NewControlMicrosoftShowDeleted() *ControlMicrosoftShowDeleted {
	return &ControlMicrosoftShowDeleted{}
}

// Find returns the first control of the given type in the list, or nil
func Find(controls []Control, typ string) Control {
	for _, c := range controls {
		if c.GetOID() == typ {
			return c
		}
	}
	return nil
}

// Decode returns a control read from the given packet, or nil if no recognized control can be made
func Decode(packet *ber.Packet) (Control, error) {
	var (
		OID         = ""
		Criticality = false
		value       *ber.Packet
	)
	switch len(packet.Children) {
	case 0:
		// at least one child is required for control type
		return nil, fmt.Errorf("at least one child is required for control type")
	case 1:
		// just type, no criticality or value
		packet.Children[0].Desc = "Control OID (" + OIDMap[OID] + ")"
		OID = packet.Children[0].Value.(string)
	case 2:
		packet.Children[0].Desc = "Control OID (" + OIDMap[OID] + ")"
		OID = packet.Children[0].Value.(string)
		// Children[1] could be criticality or value (both are optional)
		// duck-type on whether this is a boolean
		if _, ok := packet.Children[1].Value.(bool); ok {
			packet.Children[1].Desc = "Criticality"
			Criticality = packet.Children[1].Value.(bool)
		} else {
			packet.Children[1].Desc = "Control Value"
			value = packet.Children[1]
		}
	case 3:
		packet.Children[0].Desc = "Control OID (" + OIDMap[OID] + ")"
		OID = packet.Children[0].Value.(string)
		packet.Children[1].Desc = "Criticality"
		Criticality = packet.Children[1].Value.(bool)
		packet.Children[2].Desc = "Control Value"
		value = packet.Children[2]
	default:
		// more than 3 children is invalid
		return nil, fmt.Errorf("more than 3 children is invalid for controls")
	}
	switch OID {
	case OIDManageDsaIT:
		return NewControlManageDsaIT(Criticality), nil
	case OIDPaging:
		value.Desc += " (Paging)"
		c := new(ControlPaging)
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
		value.Desc = "Search Control Value"
		value.Children[0].Desc = "Paging Size"
		value.Children[1].Desc = "Cookie"
		c.PagingSize = uint32(value.Children[0].Value.(int64))
		c.Cookie = value.Children[1].Data.Bytes()
		value.Children[1].Value = c.Cookie
		return c, nil
	case OIDBeheraPasswordPolicy:
		value.Desc += " (Password Policy - Behera)"
		c := NewControlBeheraPasswordPolicy()
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
	case OIDVChuPasswordMustChange:
		c := &ControlVChuPasswordMustChange{MustChange: true}
		return c, nil
	case OIDVChuPasswordWarning:
		c := &ControlVChuPasswordWarning{Expire: -1}
		expireStr := string(value.Data.Bytes())
		expire, err := strconv.ParseInt(expireStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value as int: %s", err)
		}
		c.Expire = expire
		value.Value = c.Expire
		return c, nil
	case OIDMicrosoftNotification:
		return NewControlMicrosoftNotification(), nil
	case OIDMicrosoftShowDeleted:
		return NewControlMicrosoftShowDeleted(), nil
	default:
		c := new(ControlString)
		c.OID = OID
		c.Criticality = Criticality
		if value != nil {
			c.ControlValue = value.Value.(string)
		}
		return c, nil
	}
}

// NewControlString returns a generic control
func NewControlString(typ string, criticality bool, controlValue string) *ControlString {
	return &ControlString{
		OID:          typ,
		Criticality:  criticality,
		ControlValue: controlValue,
	}
}

// NewControlPaging returns a paging control
func NewControlPaging(pagingSize uint32) *ControlPaging {
	return &ControlPaging{PagingSize: pagingSize}
}

// NewControlBeheraPasswordPolicy returns a ControlBeheraPasswordPolicy
func NewControlBeheraPasswordPolicy() *ControlBeheraPasswordPolicy {
	return &ControlBeheraPasswordPolicy{
		Expire: -1,
		Grace:  -1,
		Error:  -1,
	}
}

func Encode(controls ...Control) *ber.Packet {
	p := ber.NewPacket(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, c := range controls {
		p.AppendChild(c.Encode())
	}
	return p
}
