package ldapclient

import (
	"log"

	"github.com/userhive/asn1/ber"
)

// DelRequest implements an LDAP deletion request
type DelRequest struct {
	// DN is the name of the directory entry to delete
	DN string
	// Controls hold optional controls to send with the request
	Controls []Control
}

func (req *DelRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypePrimitive, ApplicationDelRequest.Tag(), req.DN, "Del Request")
	pkt.Data.Write([]byte(req.DN))

	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(encodeControls(req.Controls))
	}

	return nil
}

// NewDelRequest creates a delete request for the given DN and controls
func NewDelRequest(DN string, Controls []Control) *DelRequest {
	return &DelRequest{
		DN:       DN,
		Controls: Controls,
	}
}

// Del executes the given delete request
func (l *Conn) Del(delRequest *DelRequest) error {
	msgCtx, err := l.DoRequest(delRequest)
	if err != nil {
		return err
	}
	defer l.FinishMessage(msgCtx)

	packet, err := l.ReadPacket(msgCtx)
	if err != nil {
		return err
	}

	if packet.Children[1].Tag == ApplicationDelResponse.Tag() {
		err := GetLDAPError(packet)
		if err != nil {
			return err
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}
	return nil
}
