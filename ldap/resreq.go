package ldap

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldap/ldaputil"
)

// Request is a ldap request.
type Request struct {
	ConnID     string
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	ID         int64
	Packet     *ber.Packet
}

// ReadRequest reads a request from the connection.
func ReadRequest(conn net.Conn) (*Request, error) {
	_, p, err := ber.Parse(conn)
	if err != nil {
		return nil, err
	}
	// check packet
	if len(p.Children) < 2 {
		return nil, ErrPacketHasInvalidNumberOfChildren
	}
	id, ok := p.Children[0].Value.(int64)
	if !ok {
		return nil, ErrPacketHasInvalidMessageID
	}
	if p.Children[1].Class != ber.ClassApplication {
		return nil, ErrPacketHasInvalidClass
	}
	return &Request{
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: conn.RemoteAddr(),
		ID:         id,
		Packet:     p.Children[1],
	}, nil
}

// ResponseWriter is the ldap response writer interface.
type ResponseWriter interface {
	WriteRaw([]byte) error
	WritePacket(*ber.Packet) error
	WriteMessage(*ber.Packet) error
	WriteResult(ldaputil.Application, ldaputil.Result, string, string, ...*ber.Packet) error
	WriteError(ldaputil.Application, error) error
}

// responseWriter wraps writing ldap messages.
type responseWriter struct {
	w  io.Writer
	id int64
}

// NewResponseWriter creates a new response writer for the writer and message
// id.
func NewResponseWriter(w io.Writer, id int64) ResponseWriter {
	return &responseWriter{
		w:  w,
		id: id,
	}
}

// WriteRaw writes raw bytes.
func (w *responseWriter) WriteRaw(buf []byte) error {
	if conn, ok := w.w.(interface {
		SetWriteDeadline(time.Time) error
	}); ok {
		if err := conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return err
		}
	}
	_, err := w.w.Write(buf)
	return err
}

// WritePacket writes a packet.
func (w *responseWriter) WritePacket(p *ber.Packet) error {
	// ber.PrintPacket(p)
	return w.WriteRaw(p.Bytes())
}

// WriteMessage writes a ldap message.
func (w *responseWriter) WriteMessage(p *ber.Packet) error {
	return w.WritePacket(BuildMessagePacket(w.id, p))
}

// WriteResult writes a ldap result message.
func (w *responseWriter) WriteResult(app ldaputil.Application, result ldaputil.Result, matched, msg string, extra ...*ber.Packet) error {
	res := BuildResultPacket(app, result, matched, msg)
	for _, p := range extra {
		res.AppendChild(p)
	}
	return w.WriteMessage(res)
}

// WriteError writes a ldap result error message.
func (w *responseWriter) WriteError(app ldaputil.Application, err error) error {
	if e, ok := err.(*Error); ok {
		return w.WriteResult(app, e.Result, e.Matched, e.Message)
	}
	return w.WriteResult(app, ldaputil.ResultOperationsError, "", err.Error())
}

// BuildMessagePacket builds a ldap message packet.
func BuildMessagePacket(id int64, p *ber.Packet) *ber.Packet {
	msg := ber.NewPacket(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
	)
	msg.AppendChild(
		ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			id,
		),
	)
	msg.AppendChild(p)
	return msg
}

// BuildResultPacket builds a ldap result packet.
func BuildResultPacket(app ldaputil.Application, result ldaputil.Result, matched, msg string) *ber.Packet {
	p := ber.NewPacket(
		ber.ClassApplication,
		ber.TypeConstructed,
		ber.Tag(app),
		nil,
	)
	p.AppendChild(
		ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
			int(result),
		),
	)
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			matched,
		),
	)
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			msg,
		),
	)
	return p
}

// BuildExtendedNameValuePacket builds an extended name and value packet.
func BuildExtendedNameValuePacket(request bool, name ExtendedOp, value *ber.Packet) *ber.Packet {
	tag := ber.Tag(0)
	if value != nil {
		tag = ber.TagEmbeddedPDV
	}
	p := ber.NewPacket(
		ber.ClassContext,
		ber.TypePrimitive,
		tag,
		name.String(),
	)
	if name != "" {
		_, _ = p.Data.Write([]byte(name))
	}
	if value != nil {
		p.AppendChild(value)
	}
	return p
}

// DoExtendedRequest performs an extended request against the provided context
// and client.
//
// Note: this is defined primarily for testing purposes, as the client does not
// provide any direct ability to send extended requests.
func DoExtendedRequest(ctx context.Context, cl *Client, req *ExtendedRequest) (*ExtendedResponse, error) {
	//	fmt.Fprintf(os.Stdout, "--------------------------- DoExtendedRequest\n")
	//	ber.PrintPacket(req.BuildPacket())
	//	fmt.Fprintf(os.Stdout, "--------------------------- DoExtendedRequest\n")
	msgCtx, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer cl.FinishMessage(msgCtx)
	p, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	if err := GetError(p); err != nil {
		return nil, err
	}
	if len(p.Children) != 2 {
		return nil, fmt.Errorf("invalid extended response (len=%d)", len(p.Children))
	}
	if p.Children[1].Tag != ldaputil.ApplicationExtendedResponse.Tag() {
		return nil, fmt.Errorf("invalid extended response tag %d", p.Children[1].Tag)
	}
	n := len(p.Children[1].Children)
	if n != 3 && n != 4 {
		return nil, fmt.Errorf("invalid extended response children (len=%d)", n)
	}
	result := ldaputil.Result(readInt64(p.Children[1].Children[0]))
	matched := readString(p.Children[1].Children[1])
	var value *ber.Packet
	if n == 4 {
		if p.Children[1].Children[3].Tag != ber.TagEmbeddedPDV {
			return nil, fmt.Errorf("extended response value is not embedded pdv (tag=%d)", p.Children[1].Children[3].Tag)
		}
		_, value, err = ber.Parse(p.Children[1].Children[3].Data)
		if err != nil {
			return nil, fmt.Errorf("unable to read extended response value: %v", err)
		}
	}
	return &ExtendedResponse{
		Result:    result,
		MatchedDN: matched,
		Value:     value,
	}, nil
}

func readInt64(p *ber.Packet) int64 {
	i, _ := p.Value.(int64)
	return i
}

func readString(p *ber.Packet) string {
	s, _ := p.Value.(string)
	return s
}

func readBool(p *ber.Packet) bool {
	b, _ := p.Value.(bool)
	return b
}

func readStringSlice(p *ber.Packet) []string {
	return nil
}

func readData(p *ber.Packet) []byte {
	if p.Data != nil {
		return p.Data.Bytes()
	}
	return nil
}
