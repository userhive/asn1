package ldapclient

import (
	"fmt"

	"github.com/userhive/asn1/ber"
)

// CompareRequest represents an LDAP CompareRequest operation.
type CompareRequest struct {
	DN        string
	Attribute string
	Value     string
}

func (req *CompareRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationCompareRequest.Tag(), nil, "Compare Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.DN, "DN"))
	ava := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "AttributeValueAssertion")
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.Attribute, "AttributeDesc"))
	ava.AppendChild(ber.NewPacket(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.Value, "AssertionValue"))
	pkt.AppendChild(ava)
	envelope.AppendChild(pkt)
	return nil
}

// Compare checks to see if the attribute of the dn matches value. Returns true if it does otherwise
// false with any error that occurs if any.
func (l *Conn) Compare(dn, attribute, value string) (bool, error) {
	msgCtx, err := l.DoRequest(&CompareRequest{
		DN:        dn,
		Attribute: attribute,
		Value:     value,
	})
	if err != nil {
		return false, err
	}
	defer l.FinishMessage(msgCtx)
	packet, err := l.ReadPacket(msgCtx)
	if err != nil {
		return false, err
	}
	if packet.Children[1].Tag == ApplicationCompareResponse.Tag() {
		err := GetLDAPError(packet)
		switch {
		case IsErrorWithCode(err, LDAPResultCompareTrue):
			return true, nil
		case IsErrorWithCode(err, LDAPResultCompareFalse):
			return false, nil
		default:
			return false, err
		}
	}
	return false, fmt.Errorf("unexpected Response: %d", packet.Children[1].Tag)
}
