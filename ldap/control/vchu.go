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

// GetOID returns the OID
func (c *VChuPasswordMustChange) GetOID() string {
	return OIDVChuPasswordMustChange
}

// Encode returns the ber packet representation
func (c *VChuPasswordMustChange) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *VChuPasswordMustChange) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)  Criticality: %t  MustChange: %v",
		OIDMap[OIDVChuPasswordMustChange],
		OIDVChuPasswordMustChange,
		false,
		c.MustChange)
}

// VChuPasswordWarning implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type VChuPasswordWarning struct {
	// Expire indicates the time in seconds until the password expires
	Expire int64
}

// GetOID returns the OID
func (c *VChuPasswordWarning) GetOID() string {
	return OIDVChuPasswordWarning
}

// Encode returns the ber packet representation
func (c *VChuPasswordWarning) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *VChuPasswordWarning) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)  Criticality: %t  Expire: %b",
		OIDMap[OIDVChuPasswordWarning],
		OIDVChuPasswordWarning,
		false,
		c.Expire)
}
