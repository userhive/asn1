package ldap

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/userhive/asn1/ber"
)

// Handler is the ldap handler interface.
type Handler interface {
	ServeLDAP(context.Context, ResponseWriter, *Request)
}

// HandlerFunc is the ldap handler func type.
type HandlerFunc func(context.Context, ResponseWriter, *Request)

// ServeLDAP satisfies the Handler interface.
func (f HandlerFunc) ServeLDAP(ctx context.Context, res ResponseWriter, req *Request) {
	f(ctx, res, req)
}

// ListenAndServe creates a new server for the passed handler, listening and
// serving on the specified address until the context is closed.
func ListenAndServe(ctx context.Context, addr string, h Handler, opts ...func(*net.ListenConfig)) error {
	s := &Server{Addr: addr, Handler: h}
	return s.ListenAndServe(ctx, opts...)
}

// ListenAndServe creates a new server for the passed handler, listening and
// serving TLS encrypted connections on the specified address until the context
// is closed.
func ListenAndServeTLS(ctx context.Context, addr, certFile, keyFile string, h Handler, opts ...func(*net.ListenConfig)) error {
	s := &Server{Addr: addr, Handler: h}
	return s.ListenAndServeTLS(ctx, certFile, keyFile, opts...)
}

// Session is a ldap session.
type Session struct {
	count uint
	id    string
	vals  map[string]interface{}
	sync.Mutex
}

// NewSession creates a new session
func NewSession(id string) *Session {
	return &Session{
		count: 0,
		id:    id,
		vals:  make(map[string]interface{}),
	}
}

// set sets a value.
func (s *Session) set(k string, v interface{}) {
	s.Lock()
	defer s.Unlock()
	s.vals[k] = v
}

// get retrieves a value.
func (s *Session) get(k string) interface{} {
	s.Lock()
	defer s.Unlock()
	return s.vals[k]
}

// Server is a ldap server.
type Server struct {
	Addr              string
	Handler           Handler
	ErrorLog          *log.Logger
	TLSConfig         *tls.Config
	shutdownRequested int32
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	sessions          map[net.Conn]*Session
	lastActive        chan struct{}
	activeCount       int32
}

func (s *Server) initLocked() {
	if s.ctx == nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
		s.lastActive = make(chan struct{})
	}
}

func (s *Server) activeAdd() {
	atomic.AddInt32(&s.activeCount, 1)
}

func (s *Server) activeDone() {
	if atomic.AddInt32(&s.activeCount, -1) == -1 {
		close(s.lastActive)
	}
}

func (s *Server) logf(format string, args ...interface{}) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Serve accepts incoming connections on conn.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if s.Handler == nil {
		return ErrNilHandler
	}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = make(map[net.Conn]*Session)
	}
	s.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.sessions[conn] == nil {
			s.sessions[conn] = NewSession(fmt.Sprintf("%x", md5.Sum([]byte(conn.LocalAddr().String()+"::"+conn.RemoteAddr().String()))))
		}
		s.mu.Unlock()
		go s.serve(context.WithValue(ctx, sessionKey, s.sessions[conn]), conn)
	}
	return nil
}

func (s *Server) ServeTLS(ctx context.Context, l net.Listener, certFile, keyFile string) error {
	config := s.TLSConfig
	hasCert := len(config.Certificates) > 0 || config.GetCertificate != nil
	if !hasCert || certFile != "" || keyFile != "" {
		var err error
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
	}
	tlsl := tls.NewListener(l, config)
	return s.Serve(ctx, tlsl)
}

func (s *Server) serve(ctx context.Context, conn net.Conn) {
	s.mu.Lock()
	s.initLocked()
	if atomic.LoadInt32(&s.shutdownRequested) == 1 {
		s.mu.Unlock()
		return
	}
	s.sessions[conn].Lock()
	s.sessions[conn].count++
	s.sessions[conn].Unlock()
	s.mu.Unlock()
	type requestKey struct {
		ConnID string
		ID     int64
	}
	var (
		requestsLock sync.Mutex
		requests     = map[requestKey]struct{}{}
	)
	s.activeAdd()
	// delete session
	defer func() {
		s.mu.Lock()
		s.sessions[conn].Lock()
		s.sessions[conn].count--
		if s.sessions[conn].count == 0 {
			s.sessions[conn].Unlock()
			// TODO: don't delete, but mark for deletion and clean up differently ...
			delete(s.sessions, conn)
		} else {
			s.sessions[conn].Unlock()
		}
		s.mu.Unlock()
		s.activeDone()
	}()
	for {
		// read deadline
		err := conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		switch {
		case err == io.EOF,
			err == io.ErrUnexpectedEOF,
			err != nil && atomic.LoadInt32(&s.shutdownRequested) == 1,
			err != nil && strings.Contains(err.Error(), "use of closed network connection"):
			return
		case err != nil:
			s.logf("could not set read deadline: %v", err)
			return
		}
		// read request
		req, err := ReadRequest(conn)
		switch {
		case err == io.EOF,
			err == io.ErrUnexpectedEOF,
			err == ber.ErrUnexpectedEOF,
			err != nil && atomic.LoadInt32(&s.shutdownRequested) == 1,
			err != nil && strings.Contains(err.Error(), "use of closed network connection"):
			return
		case err != nil:
			s.logf("malformed request packet, skipping: %v", err)
			continue
		}
		// handle request/response
		s.activeAdd()
		go func(req *Request) {
			defer s.activeDone()
			s.mu.Lock()
			session := s.sessions[conn]
			if session == nil {
				s.mu.Unlock()
				return
			}
			session.Lock()
			key := requestKey{
				ConnID: session.id,
				ID:     req.ID,
			}
			session.Unlock()
			s.mu.Unlock()
			requestsLock.Lock()
			if _, ok := requests[key]; ok {
				requestsLock.Unlock()
				return
			}
			requests[key] = struct{}{}
			requestsLock.Unlock()
			res := NewResponseWriter(conn, req.ID)
			defer func() {
				requestsLock.Lock()
				delete(requests, key)
				requestsLock.Unlock()
				// immediate disconnect
				if req.Packet.Tag == ApplicationUnbindRequest.Tag() {
					conn.Close()
				}
			}()
			s.Handler.ServeLDAP(WithLogf(ctx, s.logf), res, req)
		}(req)
	}
}

// ListenAndServe listens and serves ldap connections on the Server's address
// until the context is closed.
func (s *Server) ListenAndServe(ctx context.Context, opts ...func(*net.ListenConfig)) error {
	if s.Handler == nil {
		return ErrNilHandler
	}
	addr := ":ldap"
	if s.Addr != "" {
		addr = s.Addr
	}
	lc := &net.ListenConfig{}
	for _, o := range opts {
		o(lc)
	}
	l, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer l.Close()
	return s.Serve(ctx, l)
}

// ListenAndServeTLS listens and serves TLS encrypted ldap connections on the
// Server's address until the context is closed.
func (s *Server) ListenAndServeTLS(ctx context.Context, certFile, keyFile string, opts ...func(*net.ListenConfig)) error {
	if s.Handler == nil {
		return ErrNilHandler
	}
	addr := ":ldaps"
	if s.Addr != "" {
		addr = s.Addr
	}
	lc := &net.ListenConfig{}
	for _, o := range opts {
		o(lc)
	}
	l, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer l.Close()
	return s.ServeTLS(ctx, l, certFile, keyFile)
}

// Shutdown gracefully stops the server. It first closes all listeners and then
// waits for any running handlers to complete.
//
// Shutdown returns after nil all handlers have completed. ctx.Err() is
// returned if ctx is canceled.
//
// Any Serve methods return ErrShutdown after Shutdown is called.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.initLocked()
	if atomic.CompareAndSwapInt32(&s.shutdownRequested, 0, 1) {
		for conn := range s.sessions {
			conn.Close()
		}
		s.cancel()
		s.activeDone()
	}
	s.mu.Unlock()
	select {
	case <-s.lastActive:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
