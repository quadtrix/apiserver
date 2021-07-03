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

type ServerType int

const (
	ST_TCP   ServerType = 0
	ST_HTTP  ServerType = 1
	ST_HTTPS ServerType = 2
	ST_TCPS  ServerType = 3
)

type APIState int

const (
	APISTATE_OK           APIState = 200
	APISTATE_INPUT_ERROR  APIState = 405
	APISTATE_SERVER_ERROR APIState = 500
)

type APIHeader struct {
	Key    string
	Values []string
}

type APIHeaders []APIHeader

type APIContentType string

const (
	ACT_JSON APIContentType = "application/json; charset=UTF8"
	ACT_HTML APIContentType = "text/html; charset=UTF8"
	ACT_TEXT APIContentType = "text/plain; charset=UTF8"
)

type APIResponseType int

const (
	ART_TCP  APIResponseType = 0
	ART_HTTP APIResponseType = 1
)

type APIResponse struct {
	ResponseType APIResponseType
	State        APIState
	Headers      APIHeaders
	ContentType  APIContentType
	Body         []byte
	RawData      []byte
}

type Request struct {
	RequestURI  string
	Headers     APIHeaders
	RequestBody []byte
	RawRequest  []byte
}

type APIHandler func(Request) *APIResponse

// APIServer struct
type APIServer struct {
	startTime        time.Time
	stype            ServerType
	running          bool
	locked           bool
	listener         net.Listener
	ListenIP         string
	ListenPort       int
	SSL              bool
	SSLCertFile      string
	SSLKeyFile       string
	ClientCertPolicy tls.ClientAuthType
	certpool         *x509.CertPool
}

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
	return as
}

func (as APIServer) AddCA(file string) error {
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
		return errors.New("locked object")
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
	if as.locked {
		return errors.New("server is already running")
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
