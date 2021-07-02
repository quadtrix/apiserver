# apiserver
Golang simple API server supporting both basic TCP traffic and HTTP traffic (including TLS)

# Features
This simple API server supports TCP/TCPS communication and HTTP/HTTPS communication. If you want to use this API server within your organization and you're not using global CA's to sign your certificates, you can add your own CA to the trusted CA's:

    as := apiserver.New(ST_HTTPS)
    as.AddCA(<cafile>)
    
# Use in your code
To use this module in your code, run the following command:

    go get github.com/quadtrix/apiserver
   
And then import it in your code:

    import "github.com/quadtrix/apiserver"
  
# Example
A simple example to create a running server:

    package main
   
    import "github.com/quadtrix/apiserver"
   
    func handler(request apiserver.Request) apiserver.APIResponse {
      ... your handler code here ...
    }
   
    func main() {
      as := apiserver.New(ST_HTTP)
      as.Listen(handler)
    }

See the wiki pages for complete documentation
