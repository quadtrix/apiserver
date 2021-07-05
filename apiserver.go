// package apiserver Implements a basic HTTP(S) API server
package apiserver

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

// ServerType describes the type of server. TCP/TCPS, HTTP/HTTPS
type ServerType int

const (
	ST_TCP   ServerType = 0
	ST_HTTP  ServerType = 1
	ST_HTTPS ServerType = 2
	ST_TCPS  ServerType = 3
)

// APIState describes the status (state) of the response sent to the client. APIState is only used when the ServerType is either ST_HTTP or ST_HTTPS
type APIState int

const (
	APISTATE_OK           APIState = 200
	APISTATE_INPUT_ERROR  APIState = 405
	APISTATE_SERVER_ERROR APIState = 500
)

// APIHeader A single header used when ServerType is either ST_HTTP or ST_HTTPS. One APIHeader key can have multiple values
type APIHeader struct {
	Key    string
	Values []string
}

// APIHeaders list of APIHeader structs
type APIHeaders []APIHeader

// APIContentType describes the content type of the response sent to the client. A number of basic content types are already defined (ACT_...). Defining a content type outside of these examples is allowed.
type APIContentType string

const (
	ACT_JSON APIContentType = "application/json; charset=UTF8"
	ACT_HTML APIContentType = "text/html; charset=UTF8"
	ACT_TEXT APIContentType = "text/plain; charset=UTF8"
)

// APIResponseType describes the type of response the client receives, either TCP or HTTP
type APIResponseType int

const (
	ART_TCP  APIResponseType = 0
	ART_HTTP APIResponseType = 1
)

// APIResponse the response sent to the client
type APIResponse struct {
	ResponseType APIResponseType
	State        APIState
	Headers      APIHeaders
	ContentType  APIContentType
	Body         []byte
	RawData      []byte
}

// Request the request received from the client
type Request struct {
	RequestURI  string
	Headers     APIHeaders
	RequestBody []byte
	RawRequest  []byte
}

// APIHandler function to handle a request and produce a response. The handler can be assigned to the APIServer in either a call to the Listen method, or by using one or multiple RegisterContext calls.
type APIHandler func(Request) *APIResponse

// APIContext holds a registered context
type APIContext struct {
	uriPrefix string
	handler   APIHandler
}

// APIServer the server object. Create a new APIServer by calling New
type APIServer struct {
	startTime          time.Time
	stype              ServerType
	running            bool
	locked             bool
	rc                 bool
	listener           net.Listener
	ListenIP           string
	ListenPort         int
	SSL                bool
	SSLCertFile        string
	SSLKeyFile         string
	ClientCertPolicy   tls.ClientAuthType
	certpool           *x509.CertPool
	registeredContexts []APIContext
}

// New registers a new APIServer. Define the ServerType you want
func New(stype ServerType) *APIServer {
	as := new(APIServer)
	as.startTime = time.Now()
	as.stype = stype
	as.ListenIP = "0.0.0.0"
	as.ListenPort = 8080
	as.certpool, _ = x509.SystemCertPool()
	if as.certpool == nil {
		as.certpool = x509.NewCertPool()
	}
	as.ClientCertPolicy = tls.NoClientCert
	return as
}

// Add adds a new key and value, or a new value to an existing key to the APIHeaders. Value duplication is not checked.
func (ah APIHeaders) Add(key string, value string) {
	for _, hdr := range ah {
		if hdr.Key == key {
			hdr.Values = append(hdr.Values, value)
			return
		}
	}
	hdr := new(APIHeader)
	hdr.Key = key
	hdr.Values = []string{value}
	ah = append(ah, *hdr)
}

// RemoveHeader removes a header from APIHeaders
func (ah APIHeaders) RemoveHeader(key string) error {
	for i, hdr := range ah {
		if hdr.Key == key {
			if i > 0 {
				if len(ah) > i+1 {
					ah = append(ah[:i-1], ah[i+1:]...)
				} else {
					ah = ah[:i-1]
				}
			} else {
				if len(ah) > i+1 {
					ah = ah[1:]
				} else {
					ah = []APIHeader{}
				}
			}
			return nil
		}
	}
	return errors.New("key not found")
}

// RemoveValue removes a value from an APIHeader key
func (ah APIHeaders) RemoveValue(key string, value string) error {
	for i, hdr := range ah {
		if hdr.Key == key {
			for j, val := range hdr.Values {
				if val == value {
					if j > 0 {
						if len(hdr.Values) > j+1 {
							ah[i].Values = append(ah[i].Values[:j-1], ah[i].Values[j+1:]...)
						} else {
							ah[i].Values = ah[i].Values[:j-1]
						}
					} else {
						if len(hdr.Values) > j+1 {
							ah[i].Values = ah[i].Values[1:]
						} else {
							ah[i].Values = []string{}
						}
					}
				}
			}
			return nil
		}
	}
	return errors.New("key not found")
}

// Bytes returns the byte array representing all headers
func (ah APIHeaders) Bytes() (bytes []byte) {
	for _, hdr := range ah {
		for _, val := range hdr.Values {
			bytes = append(bytes, append([]byte(hdr.Key), append([]byte(": "), append([]byte(val), []byte("\r\n")...)...)...)...)
		}
	}
	return bytes
}

// AddCA adds a CA certificate to the certificate pool.
func (as APIServer) AddCA(file string) error {
	if as.running {
		return errors.New("cannot add CA on a running server")
	}
	as.lock()
	cacontent, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	ok := as.certpool.AppendCertsFromPEM(cacontent)
	as.unlock()
	if !ok {
		return errors.New("failed to add the CA to the cert pool")
	}
	return nil
}

// RegisterContext registers a URI context, assigned to a specific APIHandler. Overlapping contexts are allowed. The most specific context will be used. Call Listen(nil) when using registered contexts.
func (as APIServer) RegisterContext(context string, handler APIHandler) error {
	if as.locked {
		return errors.New("server is locked")
	}
	if as.running {
		return errors.New("cannot register context on a running server")
	}
	as.lock()
	if as.rc {
		for _, ct := range as.registeredContexts {
			if ct.uriPrefix == context {
				return errors.New("duplicate context")
			}
		}
	}
	as.rc = true
	co := APIContext{
		uriPrefix: context,
		handler:   handler,
	}
	as.registeredContexts = append(as.registeredContexts, co)
	as.unlock()
	return nil
}

func (as APIServer) lock() {
	if as.locked {
		panic(errors.New("lock mux inconsistency"))
	}
	as.locked = true
}

func (as APIServer) unlock() {
	if !as.locked {
		panic(errors.New("unlock mux inconsistency"))
	}
	as.locked = false
}

// SetServerType modifies the server type
func (as APIServer) SetServerType(stype ServerType) error {
	if as.locked {
		return errors.New("server is locked")
	}
	if as.running {
		return errors.New("cannot change server type on a running server")
	}
	if stype > 2 {
		return errors.New("unknown server type")
	}
	as.lock()
	as.stype = stype
	if as.stype == ST_HTTPS || as.stype == ST_TCPS {
		as.SSL = true
	} else {
		as.SSL = false
	}
	as.unlock()
	return nil
}

func (as APIServer) Listen(handler APIHandler) error {
	if as.running {
		return errors.New("server is already running")
	}
	if as.locked {
		return errors.New("server is locked")
	}
	if as.SSL {
		if as.SSLCertFile == "" || as.SSLKeyFile == "" {
			return errors.New("SSL server type without SSLCertFile or SSLKeyFile")
		}
		go as.listenSSL(handler)
		return nil
	} else {
		go as.listenOpen(handler)
		return nil
	}
}

func (as APIServer) listenSSL(handler APIHandler) {
	var err error
	certificate, err := tls.LoadX509KeyPair(as.SSLCertFile, as.SSLKeyFile)
	if err != nil {
		panic(err)
	}
	config := tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   as.ClientCertPolicy,
		Rand:         rand.Reader,
	}

	as.listener, err = tls.Listen("tcp", as.ListenIP+":"+fmt.Sprint(as.ListenPort), &config)
	if err != nil {
		panic(err)
	}
	as.running = true
	defer as.listener.Close()

	for {
		conn, err := as.listener.Accept()
		if err != nil {
			panic(err)
		}
		//defer conn.Close()
		req := new(Request)
		reader := bufio.NewReader(conn)
		buffer := make([]byte, 1024)
		var data []byte
		var n int = len(buffer)
		for n == len(buffer) {
			n, err = reader.Read(buffer)
			if err != nil {
				panic(err)
			}
			data = append(data, buffer...)
		}
		req.RawRequest = data
		if as.stype == ST_HTTP || as.stype == ST_HTTPS {
			// do HTTP request processing
			rawreqparts := strings.Split(string(data), "\r\n")
			req.RequestURI = rawreqparts[0]
			var rh bool = true
			if len(rawreqparts) > 1 {
				for _, reqline := range rawreqparts[1:] {
					if reqline != "" {
						if rh {
							hdr := new(APIHeader)
							hdrp := strings.Split(reqline, ": ")
							hdr.Key = hdrp[0]
							if len(hdrp) > 1 {
								hdr.Values = []string{hdrp[1]}
							}
							req.Headers = append(req.Headers, *hdr)
						} else {
							req.RequestBody = append(req.RequestBody, []byte(reqline)...)
						}
					} else {
						rh = !rh
					}
				}
			}
		}
		if as.rc {
			var lfct string = ""
			for _, context := range as.registeredContexts {
				if strings.HasPrefix(req.RequestURI, context.uriPrefix) {
					if len(lfct) < len(context.uriPrefix) {
						lfct = context.uriPrefix
						handler = context.handler
					}
				}
			}
		}
		response := handler(*req)
		wdata := as.buildWriteData(response)
		_, _ = conn.Write(wdata)
		conn.Close()
	}
}

func (as APIServer) listenOpen(handler APIHandler) {
	var err error
	as.listener, err = net.Listen("tcp", as.ListenIP+":"+fmt.Sprint(as.ListenPort))
	if err != nil {
		panic(err)
	}
	as.running = true
	defer as.listener.Close()

	for {
		conn, err := as.listener.Accept()
		if err != nil {
			panic(err)
		}
		//defer conn.Close()
		req := new(Request)
		reader := bufio.NewReader(conn)
		buffer := make([]byte, 1024)
		var data []byte
		var n int = len(buffer)
		for n == len(buffer) {
			n, err = reader.Read(buffer)
			if err != nil {
				panic(err)
			}
			data = append(data, buffer...)
		}
		req.RawRequest = data
		if as.stype == ST_HTTP || as.stype == ST_HTTPS {
			// do HTTP request processing
			rawreqparts := strings.Split(string(data), "\r\n")
			req.RequestURI = rawreqparts[0]
			var rh bool = true
			if len(rawreqparts) > 1 {
				for _, reqline := range rawreqparts[1:] {
					if reqline != "" {
						if rh {
							hdr := new(APIHeader)
							hdrp := strings.Split(reqline, ": ")
							hdr.Key = hdrp[0]
							if len(hdrp) > 1 {
								hdr.Values = []string{hdrp[1]}
							}
							req.Headers = append(req.Headers, *hdr)
						} else {
							req.RequestBody = append(req.RequestBody, []byte(reqline)...)
						}
					} else {
						rh = !rh
					}
				}
			}
		}
		if as.rc {
			var lfct string = ""
			for _, context := range as.registeredContexts {
				if strings.HasPrefix(req.RequestURI, context.uriPrefix) {
					if len(lfct) < len(context.uriPrefix) {
						lfct = context.uriPrefix
						handler = context.handler
					}
				}
			}
		}
		response := handler(*req)
		wdata := as.buildWriteData(response)
		_, _ = conn.Write(wdata)
		conn.Close()
	}
}

func (as APIServer) buildWriteData(resp *APIResponse) []byte {
	if resp.ResponseType == ART_TCP {
		return resp.RawData
	} else {
		var rd []byte
		var rc string
		switch resp.State {
		case 200:
			rc = "200 OK HTTP/1.1"
		case 405:
			rc = "405 Method not Allowed HTTP/1.1"
		case 500:
			rc = "500 Internal Server Error HTTP/1.1"
		}
		rd = append(rd, []byte(rc+"\r\n")...)
		for _, hdr := range resp.Headers {
			rd = append(rd, []byte(hdr.Key+": "+hdr.Values[0]+"\r\n")...)
		}
		rd = append(rd, []byte("\r\n")...)
		rd = append(rd, resp.Body...)
		return rd
	}
}
