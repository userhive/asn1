package ldapclient

import (
	"fmt"

	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldap/control"
)

// Adds descriptions to an LDAP Response packet for debugging
func AddLDAPDescriptions(packet *ber.Packet) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ldap: cannot process packet to add descriptions: %s", r)
		}
	}()
	packet.Desc = "LDAP Response"
	packet.Children[0].Desc = "Message ID"
	application := Application(packet.Children[1].Tag)
	packet.Children[1].Desc = application.String()
	switch application {
	case ApplicationBindRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationBindResponse:
		err = AddDefaultLDAPResponseDescriptions(packet)
	case ApplicationUnbindRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationSearchRequest:
		err = AddRequestDescriptions(packet)
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
			err = AddControlDescriptions(packet.Children[2])
		}
	case ApplicationSearchResultDone:
		err = AddDefaultLDAPResponseDescriptions(packet)
	case ApplicationModifyRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationModifyResponse:
	case ApplicationAddRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationAddResponse:
	case ApplicationDeleteRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationDeleteResponse:
	case ApplicationModifyDNRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationModifyDNResponse:
	case ApplicationCompareRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationCompareResponse:
	case ApplicationAbandonRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationSearchResultReference:
	case ApplicationExtendedRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationExtendedResponse:
	}
	return err
}

func AddControlDescriptions(packet *ber.Packet) error {
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
			child.Children[0].Desc = "Control Type (" + control.OIDMap[controlType] + ")"
		case 2:
			controlType = child.Children[0].Value.(string)
			child.Children[0].Desc = "Control Type (" + control.OIDMap[controlType] + ")"
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
			child.Children[0].Desc = "Control Type (" + control.OIDMap[controlType] + ")"
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
		case control.OIDPaging:
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
		case control.OIDBeheraPasswordPolicy:
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

func AddRequestDescriptions(packet *ber.Packet) error {
	packet.Desc = "LDAP Request"
	packet.Children[0].Desc = "Message ID"
	packet.Children[1].Desc = packet.Children[1].Tag.String()
	if len(packet.Children) == 3 {
		return AddControlDescriptions(packet.Children[2])
	}
	return nil
}

func AddDefaultLDAPResponseDescriptions(packet *ber.Packet) error {
	resultCode := uint16(ResultSuccess)
	matchedDN := ""
	description := "Success"
	if err := GetLDAPError(packet); err != nil {
		resultCode = err.(*Error).ResultCode
		matchedDN = err.(*Error).MatchedDN
		description = "Error Message"
	}
	packet.Children[1].Children[0].Desc = "Result Code (" + ResultCodeMap[resultCode] + ")"
	packet.Children[1].Children[1].Desc = "Matched DN (" + matchedDN + ")"
	packet.Children[1].Children[2].Desc = description
	if len(packet.Children[1].Children) > 3 {
		packet.Children[1].Children[3].Desc = "Referral"
	}
	if len(packet.Children) == 3 {
		return AddControlDescriptions(packet.Children[2])
	}
	return nil
}
