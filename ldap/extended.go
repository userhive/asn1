package ldap

import (
	"context"

	"github.com/userhive/asn1/ber"
)

// ExtendedOp is an extended operation identifier.
type ExtendedOp string

// String satisfies the fmt.Stringer interface.
func (op ExtendedOp) String() string {
	return string(op)
}

// ExtendedOp values.
const (
	ExtendedOpPasswordModify ExtendedOp = "1.3.6.1.4.1.4203.1.11.1"
	ExtendedOpCancel         ExtendedOp = "1.3.6.1.4.1.4203.1.11.2"
	ExtendedOpWhoAmI         ExtendedOp = "1.3.6.1.4.1.4203.1.11.3"
)

type ExtendedHandler interface {
	Extended(context.Context, *ExtendedRequest) (*ExtendedResponse, error)
}

type ExtendedHandlerFunc func(context.Context, *ExtendedRequest) (*ExtendedResponse, error)

func (f ExtendedHandlerFunc) Extended(ctx context.Context, req *ExtendedRequest) (*ExtendedResponse, error) {
	return f(ctx, req)
}

type ExtendedRequest struct {
	Name  ExtendedOp
	Value *ber.Packet
}

func ParseExtendedRequest(req *Request) (*ExtendedRequest, error) {
	if len(req.Packet.Children) < 1 {
		return nil, NewError(ResultProtocolError, "missing extended operation identifier")
	}
	oid := string(readData(req.Packet.Children[0]))
	if oid == "" {
		return nil, NewError(ResultProtocolError, "invalid extended operation identifier")
	}
	var value *ber.Packet
	switch {
	case len(req.Packet.Children) > 2:
		return nil, NewError(ResultProtocolError, "invalid extended request")
	case len(req.Packet.Children) == 2:
		var err error
		_, value, err = ber.Parse(req.Packet.Children[1].Data)
		if err != nil {
			return nil, NewError(ResultProtocolError, "invalid extended request value")
		}
	}
	return &ExtendedRequest{
		Name:  ExtendedOp(oid),
		Value: value,
	}, nil
}

func (req *ExtendedRequest) BuildPacket() *ber.Packet {
	return BuildExtendedNameValuePacket(true, req.Name, req.Value)
}

// AppendTo satisfies the Request interface.
func (req *ExtendedRequest) AppendTo(p *ber.Packet) error {
	extReq := ber.NewPacket(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationExtendedRequest.Tag(),
		nil,
		ApplicationExtendedRequest.String(),
	)
	extReq.AppendChild(req.BuildPacket())
	p.AppendChild(extReq)
	return nil
}

type ExtendedResponse struct {
	Result    Result
	MatchedDN string
	Name      ExtendedOp
	Value     *ber.Packet
}

func (res *ExtendedResponse) BuildPacket() *ber.Packet {
	return BuildExtendedNameValuePacket(false, res.Name, res.Value)
}

// Encode satisfies the Encoder interface.
func (res *ExtendedResponse) Encode(ctx context.Context, w ResponseWriter) error {
	return w.WriteResult(ApplicationExtendedResponse, res.Result, res.MatchedDN, res.Result.String(), res.BuildPacket())
}

// NewExtendedWhoAmIRequest creates an extended whoami request.
func NewExtendedWhoAmIRequest() (*ExtendedRequest, error) {
	return &ExtendedRequest{
		Name: ExtendedOpWhoAmI,
	}, nil
}

// ExtendedOpHandler is an extended op handler.
type ExtendedOpHandler map[ExtendedOp]ExtendedHandlerFunc

// Extended satisfies the ExtendedHandler interface.
func (h ExtendedOpHandler) Extended(ctx context.Context, req *ExtendedRequest) (*ExtendedResponse, error) {
	op, ok := h[req.Name]
	if !ok {
		return nil, NewErrorf(ResultOperationsError, "extended operation identifier %q not supported", req.Name)
	}
	return op.Extended(ctx, req)
}

// ExtendedWhoAmIHandlerFunc is the who am i handler func type.
type ExtendedWhoAmIHandlerFunc func(context.Context, string) (Result, string, error)

// NewExtendedWhoAmIHandler creates a new who am i handler.
//
// Note: see RFC4513 section 5.2.1.8 for format of "authzID" (prefix with dn:
// or u:).
func NewExtendedWhoAmIHandler(f ExtendedWhoAmIHandlerFunc) ExtendedHandlerFunc {
	return func(ctx context.Context, req *ExtendedRequest) (*ExtendedResponse, error) {
		sess, ok := ctx.Value(sessionKey).(*Session)
		if !ok {
			return nil, NewError(ResultOperationsError, "invalid session")
		}
		dn := sess.get("dn").(string)
		result, id, err := f(ctx, dn)
		if err != nil {
			return nil, err
		}
		return &ExtendedResponse{
			Result:    result,
			MatchedDN: dn,
			Value: ber.NewString(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagOctetString,
				id,
				"whoamiResponseValue",
			),
		}, nil
	}
}

// NewExtendedPasswordModifyRequest creates an extended password modify request.
func NewExtendedPasswordModifyRequest(id, oldPass, newPass string) (*ExtendedRequest, error) {
	value := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "passwordModifyValue")
	value.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, id, "userIdentity"))
	value.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oldPass, "oldPassword"))
	value.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newPass, "newPassword"))
	return &ExtendedRequest{
		Name:  ExtendedOpPasswordModify,
		Value: value,
	}, nil
}

// ExtendedPasswordModifyHandlerFunc is the password modify handler func type.
type ExtendedPasswordModifyHandlerFunc func(context.Context, string, string, string, string) (Result, error)

// NewExtendedPasswordModifyHandler creates a new password modify handler.
func NewExtendedPasswordModifyHandler(f ExtendedPasswordModifyHandlerFunc) ExtendedHandlerFunc {
	return func(ctx context.Context, req *ExtendedRequest) (*ExtendedResponse, error) {
		sess, ok := ctx.Value(sessionKey).(*Session)
		if !ok {
			return nil, NewError(ResultOperationsError, "invalid session")
		}
		if len(req.Value.Children) != 3 {
			return nil, NewError(ResultProtocolError, "extended password request missing values")
		}
		dn := sess.get("dn").(string)
		id, oldPass, newPass :=
			string(readData(req.Value.Children[0])),
			string(readData(req.Value.Children[1])),
			string(readData(req.Value.Children[2]))
		result, err := f(ctx, dn, id, oldPass, newPass)
		if err != nil {
			return nil, err
		}
		return &ExtendedResponse{
			Result:    result,
			MatchedDN: dn,
			Value: ber.NewPacket(
				ber.ClassUniversal,
				ber.TypeConstructed,
				ber.TagSequence,
				nil,
				"passwordModifyResponseValue",
			),
		}, nil
	}
}
