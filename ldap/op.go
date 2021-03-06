package ldap

import (
	"context"
	"strings"

	"github.com/userhive/asn1/ldap/ldaputil"
)

// Encoder is the interface for types that can be directly encoded to a
// response writer.
type Encoder interface {
	Encode(context.Context, ResponseWriter) error
}

// OpHandler is a ldap operation handler.
type OpHandler struct {
	Auth     AuthHandler
	Bind     BindHandler
	Unbind   UnbindHandler
	Search   SearchHandler
	Modify   ModifyHandler
	Add      AddHandler
	Delete   DeleteHandler
	ModifyDN ModifyDNHandler
	Compare  CompareHandler
	Abandon  AbandonHandler
	Extended ExtendedHandler
}

// ServeLDAP satisfies the Handler interface.
func (h OpHandler) ServeLDAP(ctx context.Context, res ResponseWriter, req *Request) {
	app := ldaputil.Application(req.Packet.Tag)
	opMap := map[ldaputil.Application]opFunc{
		ldaputil.ApplicationBindRequest:     h.doBind,
		ldaputil.ApplicationUnbindRequest:   h.doUnbind,
		ldaputil.ApplicationSearchRequest:   h.doSearch,
		ldaputil.ApplicationModifyRequest:   h.doModify,
		ldaputil.ApplicationAddRequest:      h.doAdd,
		ldaputil.ApplicationDeleteRequest:   h.doDelete,
		ldaputil.ApplicationModifyDNRequest: h.doModifyDN,
		ldaputil.ApplicationCompareRequest:  h.doCompare,
		ldaputil.ApplicationAbandonRequest:  h.doAbandon,
		ldaputil.ApplicationExtendedRequest: h.doExtended,
	}
	// set to the corresponding response
	op, ok := opMap[app]
	if !ok {
		_ = res.WriteError(app.Response(), NewErrorf(ldaputil.ResultOperationsError, "unsupported ldap operation (%d)", app))
		return
	}
	// add extended check middleware
	if h.Auth != nil && app == ldaputil.ApplicationExtendedRequest {
		op = h.checkExtended(op)
	}
	// add auth check middleware
	if h.Auth != nil && app != ldaputil.ApplicationBindRequest {
		op = h.checkAuth(op)
	}
	v, err := op(ctx, req)
	if err != nil {
		_ = res.WriteError(app.Response(), err)
		return
	}
	_ = v.Encode(ctx, res)
}

// opFunc is the func type of operation handlers.
type opFunc func(ctx context.Context, req *Request) (Encoder, error)

// checkAuth is an operation middleware that passes the request to the provided
// Auth handler's Auth func to determine if an operation can proceed.
func (h OpHandler) checkAuth(op opFunc) opFunc {
	return func(ctx context.Context, req *Request) (Encoder, error) {
		app := ldaputil.Application(req.Packet.Tag)
		result, err := h.Auth.Auth(ctx, app)
		if err != nil {
			return nil, err
		}
		if result != ldaputil.ResultSuccess {
			return nil, NewErrorf(result, "%s operation not authorized", strings.ToLower(strings.TrimSuffix(app.String(), "Request")))
		}
		return op(ctx, req)
	}
}

// checkExtended is an operation middleware that passes the request to the
// provided Auth handler's Extended func to determine if an operation can
// proceed.
func (h OpHandler) checkExtended(op opFunc) opFunc {
	return func(ctx context.Context, req *Request) (Encoder, error) {
		if len(req.Packet.Children) < 1 {
			return nil, NewError(ldaputil.ResultProtocolError, "missing extended operation identifier")
		}
		oid := string(readData(req.Packet.Children[0]))
		if oid == "" {
			return nil, NewError(ldaputil.ResultProtocolError, "invalid extended operation identifier")
		}
		result, err := h.Auth.Extended(ctx, ExtendedOp(oid))
		if err != nil {
			return nil, err
		}
		if result != ldaputil.ResultSuccess {
			return nil, NewErrorf(result, "extended operation %q not authorized", oid)
		}
		return op(ctx, req)
	}
}

// doBind passes the bind request to a defined Auth handler, or to the Bind
// handler if no Auth handler is defined.
func (h OpHandler) doBind(ctx context.Context, req *Request) (Encoder, error) {
	if h.Auth == nil && h.Bind == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "bind operation not supported")
	}
	bindReq, err := ParseBindRequest(req)
	if err != nil {
		return nil, err
	}
	var f func(context.Context, *BindRequest) (*BindResponse, error)
	if h.Auth != nil {
		f = h.Auth.Bind
	} else {
		f = h.Bind.Bind
	}
	return f(ctx, bindReq)
}

// doUnbind passes the unbind request to a defined Unbind handler.
func (h OpHandler) doUnbind(ctx context.Context, req *Request) (Encoder, error) {
	if h.Unbind == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "unbind operation not supported")
	}
	unbindReq, err := ParseUnbindRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.Unbind.Unbind(ctx, unbindReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doSearch passes the search request to a defined Search handler.
func (h OpHandler) doSearch(ctx context.Context, req *Request) (Encoder, error) {
	if h.Search == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "search operation not supported")
	}
	searchReq, err := ParseSearchRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.Search.Search(ctx, searchReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doModify passes the modify request to a defined Modify handler.
func (h OpHandler) doModify(ctx context.Context, req *Request) (Encoder, error) {
	if h.Modify == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "modify operation not supported")
	}
	modifyReq, err := ParseModifyRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.Modify.Modify(ctx, modifyReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doAdd passes the add request to a defined Add handler.
func (h OpHandler) doAdd(ctx context.Context, req *Request) (Encoder, error) {
	if h.Add == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "add opperation not supported")
	}
	addReq, err := ParseAddRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.Add.Add(ctx, addReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doDelete passes the delete request to a defined Delete handler.
func (h OpHandler) doDelete(ctx context.Context, req *Request) (Encoder, error) {
	if h.Delete == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "delete operation not supported")
	}
	deleteReq, err := ParseDeleteRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.Delete.Delete(ctx, deleteReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doModifyDN passes the modifyDN request to a defined ModifyDN handler.
func (h OpHandler) doModifyDN(ctx context.Context, req *Request) (Encoder, error) {
	if h.ModifyDN == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "modifyDN operation not supported")
	}
	modifyDNReq, err := ParseModifyDNRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.ModifyDN.ModifyDN(ctx, modifyDNReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doCompare passes the compare request to a defined Compare handler.
func (h OpHandler) doCompare(ctx context.Context, req *Request) (Encoder, error) {
	if h.Compare == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "compare operation not supported")
	}
	compareReq, err := ParseCompareRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.Compare.Compare(ctx, compareReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doAbandon passes the abandon request to a defined Abandon handler.
func (h OpHandler) doAbandon(ctx context.Context, req *Request) (Encoder, error) {
	if h.Abandon == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "abandon operation not supported")
	}
	abandonReq, err := ParseAbandonRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.Abandon.Abandon(ctx, abandonReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doExtended passes the extended request to a defined Extended handler.
func (h OpHandler) doExtended(ctx context.Context, req *Request) (Encoder, error) {
	if h.Extended == nil {
		return nil, NewError(ldaputil.ResultOperationsError, "extended operation not supported")
	}
	// ber.PrintPacket(req.Packet)
	extendedReq, err := ParseExtendedRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := h.Extended.Extended(ctx, extendedReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}
