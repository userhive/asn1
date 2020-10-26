package ldap

import (
	"context"
	"errors"

	"github.com/userhive/asn1/ldap/ldaputil"
)

type CompareHandler interface {
	Compare(context.Context, *CompareRequest) (*CompareResponse, error)
}

type CompareHandlerFunc func(context.Context, *CompareRequest) (*CompareResponse, error)

func (f CompareHandlerFunc) Compare(ctx context.Context, req *CompareRequest) (*CompareResponse, error) {
	return f(ctx, req)
}

type CompareRequest struct{}

func ParseCompareRequest(req *Request) (*CompareRequest, error) {
	return &CompareRequest{}, nil
}

type CompareResponse struct{}

// Encode satisfies the Encoder interface.
func (res *CompareResponse) Encode(_ context.Context, w ResponseWriter) error {
	return w.WriteError(ldaputil.ApplicationCompareResponse, errors.New("not implemented"))
}
