package ldap

import (
	"context"
	"errors"

	"github.com/userhive/asn1/ldap/ldaputil"
)

type ModifyHandler interface {
	Modify(context.Context, *ModifyRequest) (*ModifyResponse, error)
}

type ModifyHandlerFunc func(context.Context, *ModifyRequest) (*ModifyResponse, error)

func (f ModifyHandlerFunc) Modify(ctx context.Context, req *ModifyRequest) (*ModifyResponse, error) {
	return f(ctx, req)
}

type ModifyRequest struct{}

func ParseModifyRequest(req *Request) (*ModifyRequest, error) {
	return &ModifyRequest{}, nil
}

type ModifyResponse struct{}

// Encode satisfies the Encoder interface.
func (res *ModifyResponse) Encode(_ context.Context, w ResponseWriter) error {
	return w.WriteError(ldaputil.ApplicationModifyResponse, errors.New("not implemented"))
}
