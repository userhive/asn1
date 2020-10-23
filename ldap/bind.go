package ldap

import (
	"context"
)

type BindHandler interface {
	Bind(context.Context, *BindRequest) (*BindResponse, error)
}

type BindHandlerFunc func(context.Context, *BindRequest) (*BindResponse, error)

func (f BindHandlerFunc) Bind(ctx context.Context, req *BindRequest) (*BindResponse, error) {
	return f(ctx, req)
}

type BindRequest struct {
	Username string
	Password string
}

func NewBindRequest(req *Request) (*BindRequest, error) {
	if len(req.Packet.Children) != 3 {
		return nil, NewErrorf(ResultProtocolError, "invalid bind request, children missing (3 != %d)", len(req.Packet.Children))
	}
	if ver := readInt64(req.Packet.Children[0]); ver != 3 {
		return nil, NewErrorf(ResultProtocolError, "invalid protocol version (3 != %d)", ver)
	}
	return &BindRequest{
		Username: readString(req.Packet.Children[1]),
		Password: string(readData(req.Packet.Children[2])),
	}, nil
}

type BindResponse struct {
	Result    Result
	MatchedDN string
}

// Encode satisfies the Encoder interface.
func (res *BindResponse) Encode(ctx context.Context, w ResponseWriter) error {
	return w.WriteResult(ApplicationBindResponse, res.Result, res.MatchedDN, res.Result.String())
}
