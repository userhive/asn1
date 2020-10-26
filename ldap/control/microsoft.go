package control

import (
	"fmt"

	"github.com/userhive/asn1/ber"
)

// MicrosoftChangeNotification implements the control described in https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
type MicrosoftChangeNotification struct{}

// GetControl returns the Control
func (c *MicrosoftChangeNotification) GetControl() string {
	return ControlMicrosoftChangeNotification.String()
}

// Encode returns the ber packet representation
func (c *MicrosoftChangeNotification) Encode() *ber.Packet {
	p := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			ControlMicrosoftChangeNotification.String(),
			"Control OID ("+ControlMicrosoftChangeNotification.String()+")",
		),
	)
	return p
}

// String returns a human-readable description
func (c *MicrosoftChangeNotification) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)",
		ControlMicrosoftChangeNotification.String(),
		ControlMicrosoftChangeNotification)
}

// NewMicrosoftChangeNotification returns a ControlMicrosoftChangeNotification control
func NewMicrosoftChangeNotification() *MicrosoftChangeNotification {
	return &MicrosoftChangeNotification{}
}

// MicrosoftShowDeletedObjects implements the control described in https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
type MicrosoftShowDeletedObjects struct{}

// GetControl returns the OID
func (c *MicrosoftShowDeletedObjects) GetControl() string {
	return ControlMicrosoftShowDeletedObjects.String()
}

// Encode returns the ber packet representation
func (c *MicrosoftShowDeletedObjects) Encode() *ber.Packet {
	p := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			ControlMicrosoftShowDeletedObjects.String(),
			"Control OID ("+ControlMicrosoftShowDeletedObjects.String()+")",
		),
	)
	return p
}

// String returns a human-readable description
func (c *MicrosoftShowDeletedObjects) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)",
		ControlMicrosoftShowDeletedObjects.String(),
		ControlMicrosoftShowDeletedObjects,
	)
}

// NewMicrosoftShowDeletedObjects returns a ControlMicrosoftShowDeletedObjects control
func NewMicrosoftShowDeletedObjects() *MicrosoftShowDeletedObjects {
	return &MicrosoftShowDeletedObjects{}
}

// Find returns the first control of the given type in the list, or nil
func Find(controls []Control, typ string) Control {
	for _, c := range controls {
		if c.GetControl() == typ {
			return c
		}
	}
	return nil
}
