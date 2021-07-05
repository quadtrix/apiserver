package main

import (
	"crypto/tls"
	"log"

	"github.com/quadtrix/apiserver"
)

func genericHandler(req apiserver.Request) *apiserver.APIResponse {
	ar := new(apiserver.APIResponse)
	ar.State = apiserver.APISTATE_OK
	ar.ContentType = apiserver.ACT_JSON
	ar.Headers.Add("X-API", "TestAPI")
	ar.Body = []byte("{error: 0, api: {name: \"TestAPI\"}}")
	ar.RawData = append(ar.Headers.Bytes(), ar.Body...)
	ar.ResponseType = apiserver.ART_HTTP
	return ar
}

func versionHandler(req apiserver.Request) *apiserver.APIResponse {
	ar := new(apiserver.APIResponse)
	ar.State = apiserver.APISTATE_OK
	ar.ContentType = apiserver.ACT_JSON
	ar.Headers.Add("X-API", "TestAPI")
	ar.Body = []byte("{error: 0, apiversion: {name: \"TestAPI\", value: \"0.1\"}}")
	ar.RawData = append(ar.Headers.Bytes(), ar.Body...)
	ar.ResponseType = apiserver.ART_HTTP
	return ar
}

func main() {
	as := apiserver.New(apiserver.ST_HTTPS)
	as.ClientCertPolicy = tls.NoClientCert
	as.ListenIP = "127.0.0.1"
	as.ListenPort = 8888
	as.SSLCertFile = "example.crt"
	as.SSLKeyFile = "example.key"
	err := as.AddCA("example_ca.crt")
	if err != nil {
		log.Println("Error: " + err.Error())
	}
	as.RegisterContext("/", genericHandler)
	as.RegisterContext("/version", versionHandler)
	as.Listen(nil)
}
