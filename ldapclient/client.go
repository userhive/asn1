package ldapclient

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/userhive/asn1/ber"
)

// debugging type
//     - has a Printf method to write the debug output
type debugging bool

// Enable controls debugging mode.
func (debug *debugging) Enable(b bool) {
	*debug = debugging(b)
}

// Printf writes debug output.
func (debug debugging) Printf(format string, args ...interface{}) {
	if debug {
		log.Printf(format, args...)
	}
}

// PrintPacket dumps a packet.
func (debug debugging) PrintPacket(packet *ber.Packet) {
	if debug {
		packet.PrettyPrint(os.Stdout, 0)
	}
}

const (
	// MessageQuit causes the processMessages loop to exit
	MessageQuit = 0
	// MessageRequest sends a request to the server
	MessageRequest = 1
	// MessageResponse receives a response from the server
	MessageResponse = 2
	// MessageFinish indicates the client considers a particular message ID to be finished
	MessageFinish = 3
	// MessageTimeout indicates the client-specified timeout for a particular message ID has been reached
	MessageTimeout = 4
)

// PacketResponse contains the packet or error encountered reading a response
type PacketResponse struct {
	// Packet is the packet read from the server
	Packet *ber.Packet
	// Error is an error encountered while reading
	Error error
}

// ReadPacket returns the packet or an error
func (pr *PacketResponse) ReadPacket() (*ber.Packet, error) {
	if (pr == nil) || (pr.Packet == nil && pr.Error == nil) {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not retrieve response"))
	}
	return pr.Packet, pr.Error
}

type MessageContext struct {
	id int64
	// close(done) should only be called from FinishMessage()
	done chan struct{}
	// close(responses) should only be called from processMessages(), and only sent to from SendResponse()
	responses chan *PacketResponse
}

// SendResponse should only be called within the processMessages() loop which
// is also responsible for closing the responses channel.
func (msgCtx *MessageContext) SendResponse(packet *PacketResponse) {
	select {
	case msgCtx.responses <- packet:
		// Successfully sent packet to message handler.
	case <-msgCtx.done:
		// The request handler is done and will not receive more
		// packets.
	}
}

type messagePacket struct {
	Op        int
	MessageID int64
	Packet    *ber.Packet
	Context   *MessageContext
}
type SendMessageFlags uint

const (
	startTLS SendMessageFlags = 1 << iota
)

// Client is an ldap client client.
type Client struct {
	// requestTimeout is loaded atomically
	// so we need to ensure 64-bit alignment on 32-bit platforms.
	requestTimeout      int64
	conn                net.Conn
	isTLS               bool
	closing             uint32
	closeErr            atomic.Value
	isStartingTLS       bool
	Debug               debugging
	chanConfirm         chan struct{}
	messageContexts     map[int64]*MessageContext
	chanMessage         chan *messagePacket
	chanMessageID       chan int64
	wgClose             sync.WaitGroup
	outstandingRequests uint
	messageMutex        sync.Mutex
}

// DefaultTimeout is a package-level variable that sets the timeout value
// used for the Dial and DialTLS methods.
//
// WARNING: since this is a package-level variable, setting this value from
// multiple places will probably result in undesired behaviour.
var DefaultTimeout = 60 * time.Second

// DialOpt configures DialContext.
type DialOpt func(*DialContext)

// DialWithDialer updates net.Dialer in DialContext.
func DialWithDialer(d *net.Dialer) DialOpt {
	return func(dc *DialContext) {
		dc.d = d
	}
}

// DialWithTLSConfig updates tls.Config in DialContext.
func DialWithTLSConfig(tc *tls.Config) DialOpt {
	return func(dc *DialContext) {
		dc.tc = tc
	}
}

// DialContext contains necessary parameters to dial the given ldap URL.
type DialContext struct {
	d  *net.Dialer
	tc *tls.Config
}

func (dc *DialContext) dial(u *url.URL) (net.Conn, error) {
	if u.Scheme == "ldapi" {
		if u.Path == "" || u.Path == "/" {
			u.Path = "/var/run/slapd/ldapi"
		}
		return dc.d.Dial("unix", u.Path)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// we assume that error is due to missing port
		host = u.Host
		port = ""
	}
	switch u.Scheme {
	case "ldap":
		if port == "" {
			port = "389"
		}
		return dc.d.Dial("tcp", net.JoinHostPort(host, port))
	case "ldaps":
		if port == "" {
			port = "636"
		}
		return tls.DialWithDialer(dc.d, "tcp", net.JoinHostPort(host, port), dc.tc)
	}
	return nil, fmt.Errorf("Unknown scheme '%s'", u.Scheme)
}

// Dial connects to the given address on the given network using net.Dial
// and then returns a new Client for the connection.
// @deprecated Use DialURL instead.
func Dial(network, addr string) (*Client, error) {
	c, err := net.DialTimeout(network, addr, DefaultTimeout)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewClient(c, false)
	conn.Start()
	return conn, nil
}

// DialTLS connects to the given address on the given network using tls.Dial
// and then returns a new Client for the connection.
// @deprecated Use DialURL instead.
func DialTLS(network, addr string, config *tls.Config) (*Client, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: DefaultTimeout}, network, addr, config)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewClient(c, true)
	conn.Start()
	return conn, nil
}

// DialURL connects to the given ldap URL.
// The following schemas are supported: ldap://, ldaps://, ldapi://.
// On success a new Client for the connection is returned.
func DialURL(addr string, opts ...DialOpt) (*Client, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	var dc DialContext
	for _, opt := range opts {
		opt(&dc)
	}
	if dc.d == nil {
		dc.d = &net.Dialer{Timeout: DefaultTimeout}
	}
	c, err := dc.dial(u)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewClient(c, u.Scheme == "ldaps")
	conn.Start()
	return conn, nil
}

// NewClient returns a new Client using conn for network I/O.
func NewClient(conn net.Conn, isTLS bool) *Client {
	return &Client{
		conn:            conn,
		chanConfirm:     make(chan struct{}),
		chanMessageID:   make(chan int64),
		chanMessage:     make(chan *messagePacket, 10),
		messageContexts: map[int64]*MessageContext{},
		requestTimeout:  0,
		isTLS:           isTLS,
	}
}

// Start initializes goroutines to read responses and process messages
func (cl *Client) Start() {
	cl.wgClose.Add(1)
	go cl.reader()
	go cl.processMessages()
}

// IsClosing returns whether or not we're currently closing.
func (cl *Client) IsClosing() bool {
	return atomic.LoadUint32(&cl.closing) == 1
}

// setClosing sets the closing value to true
func (cl *Client) setClosing() bool {
	return atomic.CompareAndSwapUint32(&cl.closing, 0, 1)
}

// Close closes the connection.
func (cl *Client) Close() {
	cl.messageMutex.Lock()
	defer cl.messageMutex.Unlock()
	if cl.setClosing() {
		cl.Debug.Printf("Sending quit message and waiting for confirmation")
		cl.chanMessage <- &messagePacket{Op: MessageQuit}
		<-cl.chanConfirm
		close(cl.chanMessage)
		cl.Debug.Printf("Closing network connection")
		if err := cl.conn.Close(); err != nil {
			log.Println(err)
		}
		cl.wgClose.Done()
	}
	cl.wgClose.Wait()
}

// SetTimeout sets the time after a request is sent that a MessageTimeout triggers
func (cl *Client) SetTimeout(timeout time.Duration) {
	if timeout > 0 {
		atomic.StoreInt64(&cl.requestTimeout, int64(timeout))
	}
}

// Returns the next available messageID
func (cl *Client) nextMessageID() int64 {
	if messageID, ok := <-cl.chanMessageID; ok {
		return messageID
	}
	return 0
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (cl *Client) StartTLS(config *tls.Config) error {
	if cl.isTLS {
		return NewError(ErrorNetwork, errors.New("ldap: already encrypted"))
	}
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, cl.nextMessageID(), "MessageID"))
	request := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest.Tag(), nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	packet.AppendChild(request)
	cl.Debug.PrintPacket(packet)
	msgCtx, err := cl.SendMessageWithFlags(packet, startTLS)
	if err != nil {
		return err
	}
	defer cl.FinishMessage(msgCtx)
	cl.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	cl.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return err
	}
	if cl.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			cl.Close()
			return err
		}
		cl.Debug.PrintPacket(packet)
	}
	if err := GetLDAPError(packet); err == nil {
		conn := tls.Client(cl.conn, config)
		if connErr := conn.Handshake(); connErr != nil {
			cl.Close()
			return NewError(ErrorNetwork, fmt.Errorf("TLS handshake failed (%v)", connErr))
		}
		cl.isTLS = true
		cl.conn = conn
	} else {
		return err
	}
	go cl.reader()
	return nil
}

// TLSConnectionState returns the client's TLS connection state.
// The return values are their zero values if StartTLS did
// not succeed.
func (cl *Client) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := cl.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

func (cl *Client) SendMessage(packet *ber.Packet) (*MessageContext, error) {
	return cl.SendMessageWithFlags(packet, 0)
}

func (cl *Client) SendMessageWithFlags(packet *ber.Packet, flags SendMessageFlags) (*MessageContext, error) {
	if cl.IsClosing() {
		return nil, NewError(ErrorNetwork, errors.New("ldap: connection closed"))
	}
	cl.messageMutex.Lock()
	cl.Debug.Printf("flags&startTLS = %d", flags&startTLS)
	if cl.isStartingTLS {
		cl.messageMutex.Unlock()
		return nil, NewError(ErrorNetwork, errors.New("ldap: connection is in startls phase"))
	}
	if flags&startTLS != 0 {
		if cl.outstandingRequests != 0 {
			cl.messageMutex.Unlock()
			return nil, NewError(ErrorNetwork, errors.New("ldap: cannot StartTLS with outstanding requests"))
		}
		cl.isStartingTLS = true
	}
	cl.outstandingRequests++
	cl.messageMutex.Unlock()
	responses := make(chan *PacketResponse)
	messageID := packet.Children[0].Value.(int64)
	message := &messagePacket{
		Op:        MessageRequest,
		MessageID: messageID,
		Packet:    packet,
		Context: &MessageContext{
			id:        messageID,
			done:      make(chan struct{}),
			responses: responses,
		},
	}
	if !cl.sendProcessMessage(message) {
		if cl.IsClosing() {
			return nil, NewError(ErrorNetwork, errors.New("ldap: connection closed"))
		}
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not send message for unknown reason"))
	}
	return message.Context, nil
}

func (cl *Client) FinishMessage(msgCtx *MessageContext) {
	close(msgCtx.done)
	if cl.IsClosing() {
		return
	}
	cl.messageMutex.Lock()
	cl.outstandingRequests--
	if cl.isStartingTLS {
		cl.isStartingTLS = false
	}
	cl.messageMutex.Unlock()
	message := &messagePacket{
		Op:        MessageFinish,
		MessageID: msgCtx.id,
	}
	cl.sendProcessMessage(message)
}

func (cl *Client) sendProcessMessage(message *messagePacket) bool {
	cl.messageMutex.Lock()
	defer cl.messageMutex.Unlock()
	if cl.IsClosing() {
		return false
	}
	cl.chanMessage <- message
	return true
}

func (cl *Client) processMessages() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("ldap: recovered panic in processMessages: %v", err)
		}
		for messageID, msgCtx := range cl.messageContexts {
			// If we are closing due to an error, inform anyone who
			// is waiting about the error.
			if cl.IsClosing() && cl.closeErr.Load() != nil {
				msgCtx.SendResponse(&PacketResponse{Error: cl.closeErr.Load().(error)})
			}
			cl.Debug.Printf("Closing channel for MessageID %d", messageID)
			close(msgCtx.responses)
			delete(cl.messageContexts, messageID)
		}
		close(cl.chanMessageID)
		close(cl.chanConfirm)
	}()
	var messageID int64 = 1
	for {
		select {
		case cl.chanMessageID <- messageID:
			messageID++
		case message := <-cl.chanMessage:
			switch message.Op {
			case MessageQuit:
				cl.Debug.Printf("Shutting down - quit message received")
				return
			case MessageRequest:
				// Add to message list and write to network
				cl.Debug.Printf("Sending message %d", message.MessageID)
				buf := message.Packet.Bytes()
				_, err := cl.conn.Write(buf)
				if err != nil {
					cl.Debug.Printf("Error Sending Message: %s", err.Error())
					message.Context.SendResponse(&PacketResponse{Error: fmt.Errorf("unable to send request: %s", err)})
					close(message.Context.responses)
					break
				}
				// Only add to messageContexts if we were able to
				// successfully write the message.
				cl.messageContexts[message.MessageID] = message.Context
				// Add timeout if defined
				requestTimeout := time.Duration(atomic.LoadInt64(&cl.requestTimeout))
				if requestTimeout > 0 {
					go func() {
						defer func() {
							if err := recover(); err != nil {
								log.Printf("ldap: recovered panic in RequestTimeout: %v", err)
							}
						}()
						time.Sleep(requestTimeout)
						timeoutMessage := &messagePacket{
							Op:        MessageTimeout,
							MessageID: message.MessageID,
						}
						cl.sendProcessMessage(timeoutMessage)
					}()
				}
			case MessageResponse:
				cl.Debug.Printf("Receiving message %d", message.MessageID)
				if msgCtx, ok := cl.messageContexts[message.MessageID]; ok {
					msgCtx.SendResponse(&PacketResponse{message.Packet, nil})
				} else {
					log.Printf("Received unexpected message %d, %v", message.MessageID, cl.IsClosing())
					cl.Debug.PrintPacket(message.Packet)
				}
			case MessageTimeout:
				// Handle the timeout by closing the channel
				// All reads will return immediately
				if msgCtx, ok := cl.messageContexts[message.MessageID]; ok {
					cl.Debug.Printf("Receiving message timeout for %d", message.MessageID)
					msgCtx.SendResponse(&PacketResponse{message.Packet, errors.New("ldap: connection timed out")})
					delete(cl.messageContexts, message.MessageID)
					close(msgCtx.responses)
				}
			case MessageFinish:
				cl.Debug.Printf("Finished message %d", message.MessageID)
				if msgCtx, ok := cl.messageContexts[message.MessageID]; ok {
					delete(cl.messageContexts, message.MessageID)
					close(msgCtx.responses)
				}
			}
		}
	}
}

func (cl *Client) reader() {
	cleanstop := false
	defer func() {
		if err := recover(); err != nil {
			log.Printf("ldap: recovered panic in reader: %v", err)
		}
		if !cleanstop {
			cl.Close()
		}
	}()
	for {
		if cleanstop {
			cl.Debug.Printf("reader clean stopping (without closing the connection)")
			return
		}
		_, packet, err := ber.Parse(cl.conn)
		if err != nil {
			// A read error is expected here if we are closing the connection...
			if !cl.IsClosing() {
				cl.closeErr.Store(fmt.Errorf("unable to read LDAP response packet: %s", err))
				cl.Debug.Printf("reader error: %s", err)
			}
			return
		}
		if err := addLDAPDescriptions(packet); err != nil {
			cl.Debug.Printf("descriptions error: %s", err)
		}
		if len(packet.Children) == 0 {
			cl.Debug.Printf("Received bad ldap packet")
			continue
		}
		cl.messageMutex.Lock()
		if cl.isStartingTLS {
			cleanstop = true
		}
		cl.messageMutex.Unlock()
		message := &messagePacket{
			Op:        MessageResponse,
			MessageID: packet.Children[0].Value.(int64),
			Packet:    packet,
		}
		if !cl.sendProcessMessage(message) {
			return
		}
	}
}

func (cl *Client) Do(req Request) (*MessageContext, error) {
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, cl.nextMessageID(), "MessageID"))
	if err := req.AppendTo(packet); err != nil {
		return nil, err
	}
	if cl.Debug {
		cl.Debug.PrintPacket(packet)
	}
	msgCtx, err := cl.SendMessage(packet)
	if err != nil {
		return nil, err
	}
	cl.Debug.Printf("%d: returning", msgCtx.id)
	return msgCtx, nil
}

func (cl *Client) ReadPacket(msgCtx *MessageContext) (*ber.Packet, error) {
	cl.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errRespChanClosed)
	}
	packet, err := packetResponse.ReadPacket()
	cl.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, NewError(ErrorNetwork, errCouldNotRetMsg)
	}
	if cl.Debug {
		if err = addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		cl.Debug.PrintPacket(packet)
	}
	return packet, nil
}

var (
	errRespChanClosed = errors.New("ldap: response channel closed")
	errCouldNotRetMsg = errors.New("ldap: could not retrieve message")
)

type Request interface {
	AppendTo(*ber.Packet) error
}
type RequestFunc func(*ber.Packet) error

func (f RequestFunc) AppendTo(p *ber.Packet) error {
	return f(p)
}

// Application is the ldap application type.
type Application int

func (app Application) String() string {
	return app.Tag().String()
}

func (app Application) Tag() ber.Tag {
	return ber.Tag(app)
}

// Application values.
const (
	ApplicationBindRequest           Application = 0
	ApplicationBindResponse          Application = 1
	ApplicationUnbindRequest         Application = 2
	ApplicationSearchRequest         Application = 3
	ApplicationSearchResultEntry     Application = 4
	ApplicationSearchResultDone      Application = 5
	ApplicationModifyRequest         Application = 6
	ApplicationModifyResponse        Application = 7
	ApplicationAddRequest            Application = 8
	ApplicationAddResponse           Application = 9
	ApplicationDelRequest            Application = 10
	ApplicationDelResponse           Application = 11
	ApplicationModifyDNRequest       Application = 12
	ApplicationModifyDNResponse      Application = 13
	ApplicationCompareRequest        Application = 14
	ApplicationCompareResponse       Application = 15
	ApplicationAbandonRequest        Application = 16
	ApplicationSearchResultReference Application = 19
	ApplicationExtendedRequest       Application = 23
	ApplicationExtendedResponse      Application = 24
)

// Behera is the behera password policy enum.
//
// see: Behera Password Policy Draft 10 (https://tools.ietf.org/html/draft-behera-ldap-password-policy-10)
type Behera int

// Behera values.
const (
	BeheraPasswordExpired             Behera = 0
	BeheraAccountLocked               Behera = 1
	BeheraChangeAfterReset            Behera = 2
	BeheraPasswordModNotAllowed       Behera = 3
	BeheraMustSupplyOldPassword       Behera = 4
	BeheraInsufficientPasswordQuality Behera = 5
	BeheraPasswordTooShort            Behera = 6
	BeheraPasswordTooYoung            Behera = 7
	BeheraPasswordInHistory           Behera = 8
)

// BeheraPasswordPolicyErrorMap contains human readable descriptions of Behera
// Password Policy error codes
var BeheraPasswordPolicyErrorMap = map[Behera]string{
	BeheraPasswordExpired:             "Password expired",
	BeheraAccountLocked:               "Account locked",
	BeheraChangeAfterReset:            "Password must be changed",
	BeheraPasswordModNotAllowed:       "Policy prevents password modification",
	BeheraMustSupplyOldPassword:       "Policy requires old password in order to change password",
	BeheraInsufficientPasswordQuality: "Password fails quality checks",
	BeheraPasswordTooShort:            "Password is too short for policy",
	BeheraPasswordTooYoung:            "Password has been changed too recently",
	BeheraPasswordInHistory:           "New password is in list of old passwords",
}

// Adds descriptions to an LDAP Response packet for debugging
func addLDAPDescriptions(packet *ber.Packet) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewError(ErrorDebugging, fmt.Errorf("ldap: cannot process packet to add descriptions: %s", r))
		}
	}()
	packet.Desc = "LDAP Response"
	packet.Children[0].Desc = "Message ID"
	application := Application(packet.Children[1].Tag)
	packet.Children[1].Desc = application.String()
	switch application {
	case ApplicationBindRequest:
		err = addRequestDescriptions(packet)
	case ApplicationBindResponse:
		err = addDefaultLDAPResponseDescriptions(packet)
	case ApplicationUnbindRequest:
		err = addRequestDescriptions(packet)
	case ApplicationSearchRequest:
		err = addRequestDescriptions(packet)
	case ApplicationSearchResultEntry:
		packet.Children[1].Children[0].Desc = "Object Name"
		packet.Children[1].Children[1].Desc = "Attributes"
		for _, child := range packet.Children[1].Children[1].Children {
			child.Desc = "Attribute"
			child.Children[0].Desc = "Attribute Name"
			child.Children[1].Desc = "Attribute Values"
			for _, grandchild := range child.Children[1].Children {
				grandchild.Desc = "Attribute Value"
			}
		}
		if len(packet.Children) == 3 {
			err = addControlDescriptions(packet.Children[2])
		}
	case ApplicationSearchResultDone:
		err = addDefaultLDAPResponseDescriptions(packet)
	case ApplicationModifyRequest:
		err = addRequestDescriptions(packet)
	case ApplicationModifyResponse:
	case ApplicationAddRequest:
		err = addRequestDescriptions(packet)
	case ApplicationAddResponse:
	case ApplicationDelRequest:
		err = addRequestDescriptions(packet)
	case ApplicationDelResponse:
	case ApplicationModifyDNRequest:
		err = addRequestDescriptions(packet)
	case ApplicationModifyDNResponse:
	case ApplicationCompareRequest:
		err = addRequestDescriptions(packet)
	case ApplicationCompareResponse:
	case ApplicationAbandonRequest:
		err = addRequestDescriptions(packet)
	case ApplicationSearchResultReference:
	case ApplicationExtendedRequest:
		err = addRequestDescriptions(packet)
	case ApplicationExtendedResponse:
	}
	return err
}

func addControlDescriptions(packet *ber.Packet) error {
	packet.Desc = "Controls"
	for _, child := range packet.Children {
		var value *ber.Packet
		controlType := ""
		child.Desc = "Control"
		switch len(child.Children) {
		case 0:
			// at least one child is required for control type
			return fmt.Errorf("at least one child is required for control type")
		case 1:
			// just type, no criticality or value
			controlType = child.Children[0].Value.(string)
			child.Children[0].Desc = "Control Type (" + ControlTypeMap[controlType] + ")"
		case 2:
			controlType = child.Children[0].Value.(string)
			child.Children[0].Desc = "Control Type (" + ControlTypeMap[controlType] + ")"
			// Children[1] could be criticality or value (both are optional)
			// duck-type on whether this is a boolean
			if _, ok := child.Children[1].Value.(bool); ok {
				child.Children[1].Desc = "Criticality"
			} else {
				child.Children[1].Desc = "Control Value"
				value = child.Children[1]
			}
		case 3:
			// criticality and value present
			controlType = child.Children[0].Value.(string)
			child.Children[0].Desc = "Control Type (" + ControlTypeMap[controlType] + ")"
			child.Children[1].Desc = "Criticality"
			child.Children[2].Desc = "Control Value"
			value = child.Children[2]
		default:
			// more than 3 children is invalid
			return fmt.Errorf("more than 3 children for control packet found")
		}
		if value == nil {
			continue
		}
		switch controlType {
		case ControlTypePaging:
			value.Desc += " (Paging)"
			if value.Value != nil {
				_, valueChildren, err := ber.Parse(value.Data)
				if err != nil {
					return fmt.Errorf("failed to decode data bytes: %s", err)
				}
				value.Data.Truncate(0)
				value.Value = nil
				valueChildren.Children[1].Value = valueChildren.Children[1].Data.Bytes()
				value.AppendChild(valueChildren)
			}
			value.Children[0].Desc = "Real Search Control Value"
			value.Children[0].Children[0].Desc = "Paging Size"
			value.Children[0].Children[1].Desc = "Cookie"
		case ControlTypeBeheraPasswordPolicy:
			value.Desc += " (Password Policy - Behera Draft)"
			if value.Value != nil {
				_, valueChildren, err := ber.Parse(value.Data)
				if err != nil {
					return fmt.Errorf("failed to decode data bytes: %s", err)
				}
				value.Data.Truncate(0)
				value.Value = nil
				value.AppendChild(valueChildren)
			}
			sequence := value.Children[0]
			for _, child := range sequence.Children {
				if child.Tag == 0 {
					// Warning
					warningPacket := child.Children[0]
					val, err := ber.ParseInt64(warningPacket.Data.Bytes())
					if err != nil {
						return fmt.Errorf("failed to decode data bytes: %s", err)
					}
					if warningPacket.Tag == 0 {
						// timeBeforeExpiration
						value.Desc += " (TimeBeforeExpiration)"
						warningPacket.Value = val
					} else if warningPacket.Tag == 1 {
						// graceAuthNsRemaining
						value.Desc += " (GraceAuthNsRemaining)"
						warningPacket.Value = val
					}
				} else if child.Tag == 1 {
					// Error
					bs := child.Data.Bytes()
					if len(bs) != 1 || bs[0] > 8 {
						return fmt.Errorf("failed to decode data bytes: %s", "invalid PasswordPolicyResponse enum value")
					}
					val := int8(bs[0])
					child.Desc = "Error"
					child.Value = val
				}
			}
		}
	}
	return nil
}

func addRequestDescriptions(packet *ber.Packet) error {
	packet.Desc = "LDAP Request"
	packet.Children[0].Desc = "Message ID"
	packet.Children[1].Desc = packet.Children[1].Tag.String()
	if len(packet.Children) == 3 {
		return addControlDescriptions(packet.Children[2])
	}
	return nil
}

func addDefaultLDAPResponseDescriptions(packet *ber.Packet) error {
	resultCode := uint16(ResultSuccess)
	matchedDN := ""
	description := "Success"
	if err := GetLDAPError(packet); err != nil {
		resultCode = err.(*Error).ResultCode
		matchedDN = err.(*Error).MatchedDN
		description = "Error Message"
	}
	packet.Children[1].Children[0].Desc = "Result Code (" + ResultCodeMap[resultCode] + ")"
	packet.Children[1].Children[1].Desc = "Matched DN (" + matchedDN + ")"
	packet.Children[1].Children[2].Desc = description
	if len(packet.Children[1].Children) > 3 {
		packet.Children[1].Children[3].Desc = "Referral"
	}
	if len(packet.Children) == 3 {
		return addControlDescriptions(packet.Children[2])
	}
	return nil
}

// DebugBinaryFile reads and prints packets from the given filename
func DebugBinaryFile(fileName string) error {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return NewError(ErrorDebugging, err)
	}
	fmt.Fprintf(os.Stdout, "---\n%s\n---", hex.Dump(file))
	packet, err := ber.ParseBytes(file)
	if err != nil {
		return fmt.Errorf("failed to decode packet: %s", err)
	}
	if err := addLDAPDescriptions(packet); err != nil {
		return err
	}
	packet.PrettyPrint(os.Stdout, 0)
	return nil
}
