package ldaputil

import (
	"fmt"

	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldap/control"
)

// Adds descriptions to an LDAP Response packet for debugging
func AddDescriptions(p *ber.Packet) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ldap: cannot process packet to add descriptions: %s", r)
		}
	}()
	p.Desc = "LDAP Response"
	p.Children[0].Desc = "Message ID"
	application := Application(p.Children[1].Tag)
	p.Children[1].Desc = application.String()
	switch application {
	case ApplicationBindRequest:
		err = AddRequestDescriptions(p)
	case ApplicationBindResponse:
		err = AddDefaultLDAPResponseDescriptions(p)
	case ApplicationUnbindRequest:
		err = AddRequestDescriptions(p)
	case ApplicationSearchRequest:
		err = AddRequestDescriptions(p)
	case ApplicationSearchResultEntry:
		p.Children[1].Children[0].Desc = "Object Name"
		p.Children[1].Children[1].Desc = "Attributes"
		for _, child := range p.Children[1].Children[1].Children {
			child.Desc = "Attribute"
			child.Children[0].Desc = "Attribute Name"
			child.Children[1].Desc = "Attribute Values"
			for _, grandchild := range child.Children[1].Children {
				grandchild.Desc = "Attribute Value"
			}
		}
		if len(p.Children) == 3 {
			err = control.AddDescriptions(p.Children[2])
		}
	case ApplicationSearchResultDone:
		err = AddDefaultLDAPResponseDescriptions(p)
	case ApplicationModifyRequest:
		err = AddRequestDescriptions(p)
	case ApplicationModifyResponse:
	case ApplicationAddRequest:
		err = AddRequestDescriptions(p)
	case ApplicationAddResponse:
	case ApplicationDeleteRequest:
		err = AddRequestDescriptions(p)
	case ApplicationDeleteResponse:
	case ApplicationModifyDNRequest:
		err = AddRequestDescriptions(p)
	case ApplicationModifyDNResponse:
	case ApplicationCompareRequest:
		err = AddRequestDescriptions(p)
	case ApplicationCompareResponse:
	case ApplicationAbandonRequest:
		err = AddRequestDescriptions(p)
	case ApplicationSearchResultReference:
	case ApplicationExtendedRequest:
		err = AddRequestDescriptions(p)
	case ApplicationExtendedResponse:
	}
	return err
}

func AddRequestDescriptions(p *ber.Packet) error {
	p.Desc = "LDAP Request"
	p.Children[0].Desc = "Message ID"
	p.Children[1].Desc = p.Children[1].Tag.String()
	if len(p.Children) == 3 {
		return control.AddDescriptions(p.Children[2])
	}
	return nil
}

func AddDefaultLDAPResponseDescriptions(p *ber.Packet) error {
	resultCode := ResultSuccess
	matchedDN := ""
	description := "Success"
	if err := GetLDAPError(p); err != nil {
		resultCode = err.(*Error).ResultCode
		matchedDN = err.(*Error).MatchedDN
		description = "Error Message"
	}
	p.Children[1].Children[0].Desc = "Result Code (" + resultCode.String() + ")"
	p.Children[1].Children[1].Desc = "Matched DN (" + matchedDN + ")"
	p.Children[1].Children[2].Desc = description
	if len(p.Children[1].Children) > 3 {
		p.Children[1].Children[3].Desc = "Referral"
	}
	if len(p.Children) == 3 {
		return control.AddDescriptions(p.Children[2])
	}
	return nil
}
