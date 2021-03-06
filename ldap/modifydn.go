package ldap

import (
	"context"
	"errors"

	"github.com/userhive/asn1/ldap/ldaputil"
)

type ModifyDNHandler interface {
	ModifyDN(context.Context, *ModifyDNRequest) (*ModifyDNResponse, error)
}

type ModifyDNHandlerFunc func(context.Context, *ModifyDNRequest) (*ModifyDNResponse, error)

func (f ModifyDNHandlerFunc) ModifyDN(ctx context.Context, req *ModifyDNRequest) (*ModifyDNResponse, error) {
	return f(ctx, req)
}

type ModifyDNRequest struct{}

func ParseModifyDNRequest(req *Request) (*ModifyDNRequest, error) {
	return &ModifyDNRequest{}, nil
}

type ModifyDNResponse struct{}

// Encode satisfies the Encoder interface.
func (res *ModifyDNResponse) Encode(_ context.Context, w ResponseWriter) error {
	return w.WriteError(ldaputil.ApplicationModifyDNResponse, errors.New("not implemented"))
}
