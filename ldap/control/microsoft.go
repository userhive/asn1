package control

import (
	"fmt"

	"github.com/userhive/asn1/ber"
)

// MicrosoftNotification implements the control described in https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
type MicrosoftNotification struct{}

// GetOID returns the OID
func (c *MicrosoftNotification) GetOID() string {
	return OIDMicrosoftNotification
}

// Encode returns the ber packet representation
func (c *MicrosoftNotification) Encode() *ber.Packet {
	p := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDMicrosoftNotification, "Control OID ("+OIDMap[OIDMicrosoftNotification]+")"))
	return p
}

// String returns a human-readable description
func (c *MicrosoftNotification) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)",
		OIDMap[OIDMicrosoftNotification],
		OIDMicrosoftNotification)
}

// NewMicrosoftNotification returns a ControlMicrosoftNotification control
func NewMicrosoftNotification() *MicrosoftNotification {
	return &MicrosoftNotification{}
}

// MicrosoftShowDeleted implements the control described in https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
type MicrosoftShowDeleted struct{}

// GetOID returns the OID
func (c *MicrosoftShowDeleted) GetOID() string {
	return OIDMicrosoftShowDeleted
}

// Encode returns the ber packet representation
func (c *MicrosoftShowDeleted) Encode() *ber.Packet {
	p := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDMicrosoftShowDeleted, "Control OID ("+OIDMap[OIDMicrosoftShowDeleted]+")"))
	return p
}

// String returns a human-readable description
func (c *MicrosoftShowDeleted) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)",
		OIDMap[OIDMicrosoftShowDeleted],
		OIDMicrosoftShowDeleted)
}

// NewMicrosoftShowDeleted returns a ControlMicrosoftShowDeleted control
func NewMicrosoftShowDeleted() *MicrosoftShowDeleted {
	return &MicrosoftShowDeleted{}
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
