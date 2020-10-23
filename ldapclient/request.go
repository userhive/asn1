package ldapclient

import (
	"errors"

	"github.com/userhive/asn1/ber"
)

var (
	errRespChanClosed = errors.New("ldap: response channel closed")
	errCouldNotRetMsg = errors.New("ldap: could not retrieve message")
)

type Request interface {
	AppendTo(*ber.Packet) error
}

type RequestFunc func(*ber.Packet) error

func (f RequestFunc) AppendTo(p *ber.Packet) error {
	return f(p)
}

func (l *Conn) DoRequest(req Request) (*MessageContext, error) {
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
	if err := req.AppendTo(packet); err != nil {
		return nil, err
	}

	if l.Debug {
		l.Debug.PrintPacket(packet)
	}

	msgCtx, err := l.SendMessage(packet)
	if err != nil {
		return nil, err
	}
	l.Debug.Printf("%d: returning", msgCtx.id)
	return msgCtx, nil
}

func (l *Conn) ReadPacket(msgCtx *MessageContext) (*ber.Packet, error) {
	l.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errRespChanClosed)
	}
	packet, err := packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}

	if packet == nil {
		return nil, NewError(ErrorNetwork, errCouldNotRetMsg)
	}

	if l.Debug {
		if err = addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		l.Debug.PrintPacket(packet)
	}
	return packet, nil
}
