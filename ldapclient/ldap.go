// package ldapclient provides basic LDAP v3 functionality.
package ldapclient

//go:generate stringer -type Application -trimprefix Application
import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/userhive/asn1/ber"
)

// Application is the ldap application type.
type Application int

func (app Application) String() string {
	return app.Tag().String()
}

func (app Application) Tag() ber.Tag {
	return ber.Tag(app)
}

// Application values.
const (
	ApplicationBindRequest           Application = 0
	ApplicationBindResponse          Application = 1
	ApplicationUnbindRequest         Application = 2
	ApplicationSearchRequest         Application = 3
	ApplicationSearchResultEntry     Application = 4
	ApplicationSearchResultDone      Application = 5
	ApplicationModifyRequest         Application = 6
	ApplicationModifyResponse        Application = 7
	ApplicationAddRequest            Application = 8
	ApplicationAddResponse           Application = 9
	ApplicationDelRequest            Application = 10
	ApplicationDelResponse           Application = 11
	ApplicationModifyDNRequest       Application = 12
	ApplicationModifyDNResponse      Application = 13
	ApplicationCompareRequest        Application = 14
	ApplicationCompareResponse       Application = 15
	ApplicationAbandonRequest        Application = 16
	ApplicationSearchResultReference Application = 19
	ApplicationExtendedRequest       Application = 23
	ApplicationExtendedResponse      Application = 24
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

// Adds descriptions to an LDAP Response packet for debugging
func addLDAPDescriptions(packet *ber.Packet) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewError(ErrorDebugging, fmt.Errorf("ldap: cannot process packet to add descriptions: %s", r))
		}
	}()
	packet.Desc = "LDAP Response"
	packet.Children[0].Desc = "Message ID"
	application := Application(packet.Children[1].Tag)
	packet.Children[1].Desc = application.String()
	switch application {
	case ApplicationBindRequest:
		err = addRequestDescriptions(packet)
	case ApplicationBindResponse:
		err = addDefaultLDAPResponseDescriptions(packet)
	case ApplicationUnbindRequest:
		err = addRequestDescriptions(packet)
	case ApplicationSearchRequest:
		err = addRequestDescriptions(packet)
	case ApplicationSearchResultEntry:
		packet.Children[1].Children[0].Desc = "Object Name"
		packet.Children[1].Children[1].Desc = "Attributes"
		for _, child := range packet.Children[1].Children[1].Children {
			child.Desc = "Attribute"
			child.Children[0].Desc = "Attribute Name"
			child.Children[1].Desc = "Attribute Values"
			for _, grandchild := range child.Children[1].Children {
				grandchild.Desc = "Attribute Value"
			}
		}
		if len(packet.Children) == 3 {
			err = addControlDescriptions(packet.Children[2])
		}
	case ApplicationSearchResultDone:
		err = addDefaultLDAPResponseDescriptions(packet)
	case ApplicationModifyRequest:
		err = addRequestDescriptions(packet)
	case ApplicationModifyResponse:
	case ApplicationAddRequest:
		err = addRequestDescriptions(packet)
	case ApplicationAddResponse:
	case ApplicationDelRequest:
		err = addRequestDescriptions(packet)
	case ApplicationDelResponse:
	case ApplicationModifyDNRequest:
		err = addRequestDescriptions(packet)
	case ApplicationModifyDNResponse:
	case ApplicationCompareRequest:
		err = addRequestDescriptions(packet)
	case ApplicationCompareResponse:
	case ApplicationAbandonRequest:
		err = addRequestDescriptions(packet)
	case ApplicationSearchResultReference:
	case ApplicationExtendedRequest:
		err = addRequestDescriptions(packet)
	case ApplicationExtendedResponse:
	}
	return err
}

func addControlDescriptions(packet *ber.Packet) error {
	packet.Desc = "Controls"
	for _, child := range packet.Children {
		var value *ber.Packet
		controlType := ""
		child.Desc = "Control"
		switch len(child.Children) {
		case 0:
			// at least one child is required for control type
			return fmt.Errorf("at least one child is required for control type")
		case 1:
			// just type, no criticality or value
			controlType = child.Children[0].Value.(string)
			child.Children[0].Desc = "Control Type (" + ControlTypeMap[controlType] + ")"
		case 2:
			controlType = child.Children[0].Value.(string)
			child.Children[0].Desc = "Control Type (" + ControlTypeMap[controlType] + ")"
			// Children[1] could be criticality or value (both are optional)
			// duck-type on whether this is a boolean
			if _, ok := child.Children[1].Value.(bool); ok {
				child.Children[1].Desc = "Criticality"
			} else {
				child.Children[1].Desc = "Control Value"
				value = child.Children[1]
			}
		case 3:
			// criticality and value present
			controlType = child.Children[0].Value.(string)
			child.Children[0].Desc = "Control Type (" + ControlTypeMap[controlType] + ")"
			child.Children[1].Desc = "Criticality"
			child.Children[2].Desc = "Control Value"
			value = child.Children[2]
		default:
			// more than 3 children is invalid
			return fmt.Errorf("more than 3 children for control packet found")
		}
		if value == nil {
			continue
		}
		switch controlType {
		case ControlTypePaging:
			value.Desc += " (Paging)"
			if value.Value != nil {
				_, valueChildren, err := ber.Parse(value.Data)
				if err != nil {
					return fmt.Errorf("failed to decode data bytes: %s", err)
				}
				value.Data.Truncate(0)
				value.Value = nil
				valueChildren.Children[1].Value = valueChildren.Children[1].Data.Bytes()
				value.AppendChild(valueChildren)
			}
			value.Children[0].Desc = "Real Search Control Value"
			value.Children[0].Children[0].Desc = "Paging Size"
			value.Children[0].Children[1].Desc = "Cookie"
		case ControlTypeBeheraPasswordPolicy:
			value.Desc += " (Password Policy - Behera Draft)"
			if value.Value != nil {
				_, valueChildren, err := ber.Parse(value.Data)
				if err != nil {
					return fmt.Errorf("failed to decode data bytes: %s", err)
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
						return fmt.Errorf("failed to decode data bytes: %s", err)
					}
					if warningPacket.Tag == 0 {
						// timeBeforeExpiration
						value.Desc += " (TimeBeforeExpiration)"
						warningPacket.Value = val
					} else if warningPacket.Tag == 1 {
						// graceAuthNsRemaining
						value.Desc += " (GraceAuthNsRemaining)"
						warningPacket.Value = val
					}
				} else if child.Tag == 1 {
					// Error
					bs := child.Data.Bytes()
					if len(bs) != 1 || bs[0] > 8 {
						return fmt.Errorf("failed to decode data bytes: %s", "invalid PasswordPolicyResponse enum value")
					}
					val := int8(bs[0])
					child.Desc = "Error"
					child.Value = val
				}
			}
		}
	}
	return nil
}

func addRequestDescriptions(packet *ber.Packet) error {
	packet.Desc = "LDAP Request"
	packet.Children[0].Desc = "Message ID"
	packet.Children[1].Desc = packet.Children[1].Tag.String()
	if len(packet.Children) == 3 {
		return addControlDescriptions(packet.Children[2])
	}
	return nil
}

func addDefaultLDAPResponseDescriptions(packet *ber.Packet) error {
	resultCode := uint16(LDAPResultSuccess)
	matchedDN := ""
	description := "Success"
	if err := GetLDAPError(packet); err != nil {
		resultCode = err.(*Error).ResultCode
		matchedDN = err.(*Error).MatchedDN
		description = "Error Message"
	}
	packet.Children[1].Children[0].Desc = "Result Code (" + LDAPResultCodeMap[resultCode] + ")"
	packet.Children[1].Children[1].Desc = "Matched DN (" + matchedDN + ")"
	packet.Children[1].Children[2].Desc = description
	if len(packet.Children[1].Children) > 3 {
		packet.Children[1].Children[3].Desc = "Referral"
	}
	if len(packet.Children) == 3 {
		return addControlDescriptions(packet.Children[2])
	}
	return nil
}

// DebugBinaryFile reads and prints packets from the given filename
func DebugBinaryFile(fileName string) error {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return NewError(ErrorDebugging, err)
	}
	fmt.Fprintf(os.Stdout, "---\n%s\n---", hex.Dump(file))
	packet, err := ber.ParseBytes(file)
	if err != nil {
		return fmt.Errorf("failed to decode packet: %s", err)
	}
	if err := addLDAPDescriptions(packet); err != nil {
		return err
	}
	packet.PrettyPrint(os.Stdout, 0)
	return nil
}
