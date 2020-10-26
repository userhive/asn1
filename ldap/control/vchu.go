package control

import (
	"fmt"

	"github.com/userhive/asn1/ber"
)

// VChuPasswordMustChange implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type VChuPasswordMustChange struct {
	// MustChange indicates if the password is required to be changed
	MustChange bool
}

// GetControl returns the OID
func (c *VChuPasswordMustChange) GetControl() string {
	return ControlVChuPasswordMustChange.String()
}

// Encode returns the ber packet representation
func (c *VChuPasswordMustChange) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *VChuPasswordMustChange) String() string {
	return fmt.Sprintf(
		"Control OID: %s Criticality: %t  MustChange: %v",
		ControlVChuPasswordMustChange,
		false,
		c.MustChange,
	)
}

// VChuPasswordWarning implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type VChuPasswordWarning struct {
	// Expire indicates the time in seconds until the password expires
	Expire int64
}

// GetControl returns the OID
func (c *VChuPasswordWarning) GetControl() string {
	return ControlVChuPasswordWarning.String()
}

// Encode returns the ber packet representation
func (c *VChuPasswordWarning) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *VChuPasswordWarning) String() string {
	return fmt.Sprintf(
		"Control OID: %s Criticality: %t  Expire: %b",
		ControlVChuPasswordWarning,
		false,
		c.Expire,
	)
}
