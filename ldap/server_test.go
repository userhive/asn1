package ldap

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/userhive/asn1/ldap/ldaputil"
)

func TestBindNotSupported(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("cn=username,dc=example,dc=com", "password"); !strings.Contains(err.Error(), "bind operation not supported") {
		t.Errorf("expected bind operation not supported error, got: %v", err)
	}
}

func TestSearchNotSupported(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := NewClientSearchRequest(
		"dc=example,dc=com", ScopeWholeSubtree, DerefAliasesNever, 0, 0, false,
		"(&(objectClass=organizationalPerson))",
		[]string{"dn", "cn"},
	)
	if _, err := conn.Search(req); !strings.Contains(err.Error(), "search operation not supported") {
		t.Errorf("expected search operation not supported error, got: %v", err)
	}
}

func TestBind(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Bind: newTestSessionAuth("cn=username,dc=example,dc=com", "password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("cn=username,dc=example,dc=com", "password"); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestBindBadUser(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Bind: newTestSessionAuth("cn=username,dc=example,dc=com", "password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = conn.Bind("cn=baduser,dc=example,dc=com", "password")
	switch {
	case err == nil:
		t.Errorf("expected no such object error, got nil")
	case err != nil && !strings.Contains(err.Error(), "NoSuchObject"):
		t.Errorf("expected no such object error, got: %v", err)
	}
}

func TestBindBadPassword(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Bind: newTestSessionAuth("cn=username,dc=example,dc=com", "password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = conn.Bind("cn=username,dc=example,dc=com", "badpassword")
	switch {
	case err == nil:
		t.Errorf("expected invalid credentials error, got nil")
	case err != nil && !strings.Contains(err.Error(), "InvalidCredentials"):
		t.Errorf("expected invalid credentials error, got: %v", err)
	}
}

func TestSearch(t *testing.T) {
	return
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u, searchHandler := newTestSearchHandler(5, "dc=example,dc=com")
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Search: searchHandler,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := NewClientSearchRequest(
		"dc=example,dc=com", ScopeWholeSubtree, DerefAliasesNever, 0, 0, false,
		"(&(objectClass=organizationalPerson))",
		[]string{"dn", "cn"},
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if len(res.Entries) != len(u.entries) {
		t.Errorf("expected entries to be same length as users: (%d!=%d)", len(u.entries), len(res.Entries))
	}
}

func TestLDAPSearch(t *testing.T) {
	t.Parallel()
	return
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Bind: newTestSessionAuth("cn=username,dc=example,dc=com", "password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	out, err := ldapExec(ctx, "search", addr, "cn=username,dc=example,dc=com", "password", "-b", "dc=example,dc=com", "-LLL")
	if err != nil {
		t.Fatalf("expected no error, got: %v\n%s\n", err, out)
	}
	t.Logf(">>> out\n%s\n<<<", out)
}

func TestExtendedWhoAmI(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Auth:     newTestSessionAuth("cn=username,dc=example,dc=com", "password"),
		Extended: newTestExtendedHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("cn=username,dc=example,dc=com", "password"); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	req, err := NewExtendedWhoAmIRequest()
	if err != nil {
		t.Fatal(err)
	}
	res, err := DoExtendedRequest(ctx, conn, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if res.Result != ldaputil.ResultSuccess {
		t.Errorf("expected result success, got: %s (%d)", res.Result, res.Result)
	}
	if res.Value == nil {
		t.Fatal("expected non-nil extended response value")
	}
	if u := string(readData(res.Value)); u != "u:username" {
		t.Errorf("expected u:username, got: %q", u)
	}
}

func TestLDAPWhoAmI(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Auth:     newTestSessionAuth("cn=username,dc=example,dc=com", "password"),
		Extended: newTestExtendedHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	out, err := ldapExec(ctx, "whoami", addr, "cn=username,dc=example,dc=com", "password")
	if err != nil {
		t.Fatalf("expected no error, got: %v\n%s\n", err, out)
	}
	re := regexp.MustCompile(`(?m)^u:username$`)
	if !re.MatchString(out) {
		t.Errorf("expected response of u:username, got:\n%s", out)
	}
}

func TestExtendedPasswordModify(t *testing.T) {
	return
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Auth:     newTestSessionAuth("cn=username,dc=example,dc=com", "password"),
		Extended: newTestExtendedHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("cn=username,dc=example,dc=com", "password"); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	req, err := NewExtendedWhoAmIRequest()
	if err != nil {
		t.Fatal(err)
	}
	res, err := DoExtendedRequest(ctx, conn, req)
	if err != nil {
		t.Fatal(err)
	}
	if u := res.Value.Data.String(); u != "u:username" {
		t.Fatalf("expected u:username, got: %s", u)
	}

	req, err = NewExtendedPasswordModifyRequest("cn=username,dc=example,dc=com", "password", "newpassword")
	if err != nil {
		t.Fatal(err)
	}
	res, err = DoExtendedRequest(ctx, conn, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if res.Result != ldaputil.ResultSuccess {
		t.Errorf("expected result success, got: %s (%d)", res.Result, res.Result)
	}
	if res.Value == nil {
		t.Fatal("expected non-nil extended response value")
	}
}

func TestLDAPPasswordModify(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, addr, err := newTestServer(ctx, t, OpHandler{
		Auth:     newTestSessionAuth("cn=username,dc=example,dc=com", "password"),
		Extended: newTestExtendedHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	out, err := ldapExec(ctx, "passwd", addr, "cn=username,dc=example,dc=com", "password", "-a", "password", "-s", "newpassword", "someuser")
	if err != nil {
		t.Fatalf("expected no error, got: %v\n%s\n", err, out)
	}
	re := regexp.MustCompile(`(?m)^Result:\s+Success\s+\(0\)$`)
	if !re.MatchString(out) {
		t.Errorf("expected response ldaputil.Result: Success, got:\n%s", out)
	}
}

type user struct {
	name   string
	suffix string
}

type users struct {
	row     int
	entries []user
}

func newUsers(count int, suffix string) *users {
	u := &users{
		row:     -1,
		entries: make([]user, count),
	}
	for i := 0; i < count; i++ {
		u.entries[i] = user{name: fmt.Sprintf("user%d", i), suffix: suffix}
	}
	return u
}

func (u *users) Next() bool {
	u.row++
	return u.row < len(u.entries)
}

func (u *users) Err() error {
	return nil
}

func (u *users) Scan(v ...interface{}) error {
	return nil
}

func (u *users) Close() error {
	return nil
}

type searchHandler struct {
	users *users
}

func (h searchHandler) Search(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
	return &SearchResponse{
		Result:    ldaputil.ResultSuccess,
		MatchedDN: "",
		// SearchResult: h.users,
	}, nil
}

func newTestSearchHandler(count int, suffix string) (*users, SearchHandler) {
	u := newUsers(count, suffix)
	return u, searchHandler{users: u}
}

type sessionHandler struct {
	username string
	password string
	auth     map[ldaputil.Application]bool
	extended map[ExtendedOp]bool
}

func newTestSessionAuth(username, password string) AuthHandler {
	h := sessionHandler{
		username: username,
		password: password,
		auth: map[ldaputil.Application]bool{
			ldaputil.ApplicationExtendedRequest: true,
			ldaputil.ApplicationModifyRequest:   false,
			ldaputil.ApplicationSearchRequest:   true,
		},
		extended: map[ExtendedOp]bool{
			ExtendedOpWhoAmI:         true,
			ExtendedOpPasswordModify: true,
		},
	}
	return NewSessionAuthHandler(h.Bind, h.Auth, h.Extended)
}

func newTestExtendedHandler() ExtendedHandler {
	return ExtendedOpHandler{
		ExtendedOpWhoAmI: NewExtendedWhoAmIHandler(func(ctx context.Context, dn string) (ldaputil.Result, string, error) {
			return ldaputil.ResultSuccess, "u:" + dn[strings.Index(dn, "=")+1:strings.Index(dn, ",")], nil
		}),
		ExtendedOpPasswordModify: NewExtendedPasswordModifyHandler(func(ctx context.Context, dn, id, oldPass, newPass string) (ldaputil.Result, error) {
			return ldaputil.ResultSuccess, nil
		}),
	}
}

func (h sessionHandler) Bind(ctx context.Context, username, password string) (ldaputil.Result, error) {
	if h.username != username {
		return ldaputil.ResultNoSuchObject, nil
	}
	if password == "" {
		return ldaputil.ResultUnwillingToPerform, nil
	}
	if h.password != password {
		return ldaputil.ResultInvalidCredentials, nil
	}
	return ldaputil.ResultSuccess, nil
}

func (h sessionHandler) Auth(ctx context.Context, app ldaputil.Application, username string) (ldaputil.Result, error) {
	if h.auth[app] && h.username == username {
		return ldaputil.ResultSuccess, nil
	}
	return ldaputil.ResultInsufficientAccessRights, nil
}

func (h sessionHandler) Extended(ctx context.Context, op ExtendedOp, username string) (ldaputil.Result, error) {
	if h.extended[op] && h.username == username {
		return ldaputil.ResultSuccess, nil
	}
	return ldaputil.ResultInsufficientAccessRights, nil
}

func newTestServer(ctx context.Context, t *testing.T, h Handler) (*Server, string, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, "", err
	}
	s := &Server{
		Handler:  h,
		ErrorLog: log.New(testLogger{t.Logf}, "", 0),
	}
	go s.Serve(ctx, l)
	return s, l.Addr().String(), nil
}

type testLogger struct {
	logf func(string, ...interface{})
}

func (tl testLogger) Write(buf []byte) (int, error) {
	tl.logf(string(buf))
	return len(buf), nil
}

func ldapExec(ctx context.Context, typ, addr, user, pass string, params ...string) (string, error) {
	args := []string{
		"-H", "ldap://" + addr,
		"-D", user,
		"-x", "-w", pass,
	}
	args = append(args, params...)
	cmd := exec.CommandContext(ctx, "ldap"+typ, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
