package ldap

import (
	"context"
	"errors"
)

type AddHandler interface {
	Add(context.Context, *AddRequest) (*AddResponse, error)
}

type AddHandlerFunc func(context.Context, *AddRequest) (*AddResponse, error)

func (f AddHandlerFunc) Add(ctx context.Context, req *AddRequest) (*AddResponse, error) {
	return f(ctx, req)
}

type AddRequest struct{}

func NewAddRequest(req *Request) (*AddRequest, error) {
	return &AddRequest{}, nil
}

type AddResponse struct{}

// Encode satisfies the Encoder interface.
func (res *AddResponse) Encode(_ context.Context, w ResponseWriter) error {
	return w.WriteError(ApplicationAddResponse, errors.New("not implemented"))
}
