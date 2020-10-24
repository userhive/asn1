package ldap

import (
	"context"
)

type UnbindHandler interface {
	Unbind(context.Context, *UnbindRequest) (*UnbindResponse, error)
}

type UnbindHandlerFunc func(context.Context, *UnbindRequest) (*UnbindResponse, error)

func (f UnbindHandlerFunc) Unbind(ctx context.Context, req *UnbindRequest) (*UnbindResponse, error) {
	return f(ctx, req)
}

type UnbindRequest struct{}

func ParseUnbindRequest(req *Request) (*UnbindRequest, error) {
	return &UnbindRequest{}, nil
}

type UnbindResponse struct{}

// Encode satisfies the Encoder interface.
func (res *UnbindResponse) Encode(context.Context, ResponseWriter) error {
	// unbind is special case where no result is sent to the client. instead,
	// the server immediately disconnects.
	return nil
}
