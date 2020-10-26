package control

import (
	"fmt"

	"github.com/userhive/asn1/ber"
)

// Behera is the behera password policy enum.
//
// see: Behera Password Policy Draft 10 (https://tools.ietf.org/html/draft-behera-ldap-password-policy-10)
type Behera int

// Behera values.
const (
	BeheraPasswordExpired             Behera = 0
	BeheraAccountLocked               Behera = 1
	BeheraChangeAfterReset            Behera = 2
	BeheraPasswordModNotAllowed       Behera = 3
	BeheraMustSupplyOldPassword       Behera = 4
	BeheraInsufficientPasswordQuality Behera = 5
	BeheraPasswordTooShort            Behera = 6
	BeheraPasswordTooYoung            Behera = 7
	BeheraPasswordInHistory           Behera = 8
)

// BeheraPasswordPolicyErrorMap contains human readable descriptions of Behera
// Password Policy error codes
var BeheraPasswordPolicyErrorMap = map[Behera]string{
	BeheraPasswordExpired:             "Password expired",
	BeheraAccountLocked:               "Account locked",
	BeheraChangeAfterReset:            "Password must be changed",
	BeheraPasswordModNotAllowed:       "Policy prevents password modification",
	BeheraMustSupplyOldPassword:       "Policy requires old password in order to change password",
	BeheraInsufficientPasswordQuality: "Password fails quality checks",
	BeheraPasswordTooShort:            "Password is too short for policy",
	BeheraPasswordTooYoung:            "Password has been changed too recently",
	BeheraPasswordInHistory:           "New password is in list of old passwords",
}

// BeheraPasswordPolicy implements the control described in https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
type BeheraPasswordPolicy struct {
	// Expire contains the number of seconds before a password will expire
	Expire int64
	// Grace indicates the remaining number of times a user will be allowed to authenticate with an expired password
	Grace int64
	// Error indicates the error code
	Error int8
	// ErrorString is a human readable error
	ErrorString string
}

// NewBeheraPasswordPolicy returns a ControlBeheraPasswordPolicy
func NewBeheraPasswordPolicy() *BeheraPasswordPolicy {
	return &BeheraPasswordPolicy{
		Expire: -1,
		Grace:  -1,
		Error:  -1,
	}
}

// GetControl returns the Control
func (c *BeheraPasswordPolicy) GetControl() string {
	return string(ControlBeheraPasswordPolicy)
}

// Encode returns the ber packet representation
func (c *BeheraPasswordPolicy) Encode() *ber.Packet {
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
			ControlBeheraPasswordPolicy.String(),
		),
	)
	return p
}

// String returns a human-readable description
func (c *BeheraPasswordPolicy) String() string {
	return fmt.Sprintf(
		"Control OID: %s (%q)  Criticality: %t  Expire: %d  Grace: %d  Error: %d, ErrorString: %s",
		ControlBeheraPasswordPolicy.String(),
		ControlBeheraPasswordPolicy,
		false,
		c.Expire,
		c.Grace,
		c.Error,
		c.ErrorString,
	)
}
