package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"log"
	"net/http"
)

func printHeader(r *http.Request) {
	log.Print(">>>>>>>>>>>>>>>> Header <<<<<<<<<<<<<<<< \n")
	// Loop over header names
	for name, values := range r.Header {
		// Loop over all values for the name.
		for _, value := range values {
			log.Printf("%v:%v", name, value)
		}
	}
	log.Print(">>>>>>>>>>>>>>>> Header <<<<<<<<<<<<<<<< \n")
}

func printConnState(state *tls.ConnectionState) {
	log.Print(">>>>>>>>>>>>>>>> State <<<<<<<<<<<<<<<< \n")

	log.Printf("Version: %x \n", state.Version)
	log.Printf("HandshakeComplete: %t \n", state.HandshakeComplete)
	log.Printf("DidResume: %t\n", state.DidResume)
	log.Printf("CipherSuite: %x\n", state.CipherSuite)
	log.Printf("NegotiatedProtocol: %s\n", state.NegotiatedProtocol)
	log.Printf("NegotiatedProtocolIsMutual: %t/n", state.NegotiatedProtocolIsMutual)

	log.Print("Certificate chain:")
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		log.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", i, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		log.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
	}
	log.Print(">>>>>>>>>>>>>>>> State <<<<<<<<<<<<<<<< \n")
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	log.Print(">>>>>>>>>>>>>>>>> Start <<<<<<<<<<<<<<<<<<\n")
	printHeader(r)
	if r.TLS != nil {
		printConnState(r.TLS)
	}
	log.Print(">>>>>>>>>>>>>>>>> End <<<<<<<<<<<<<<<<<<\n")
	io.WriteString(w, "Logs received\n")
	log.Print("logs recieved\n")
}

func main() {
	sslPort := 443

	// Set up a /hello resource handler
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Base path hit\n")
	})
	handler.HandleFunc("/logs", helloHandler)

	// load CA certificate file and add it to list of client CAs
	caCertFile, err := os.ReadFile("/certs/ca.crt")
	if err != nil {
		log.Fatalf("error reading CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertFile)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:                caCertPool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS12,
		// CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		// PreferServerCipherSuites: true,
		// CipherSuites: []uint16{
		// 	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		// 	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		// 	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		// 	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		// 	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		// 	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		// },
	}
	tlsConfig.BuildNameToCertificate()

	// serve on port 8443 of local host
	server := http.Server{
		Addr:      fmt.Sprintf(":%d", sslPort),
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	log.Printf("(HTTPS) Listen on :%d\n", sslPort)
	if err := server.ListenAndServeTLS("/certs/server.crt", "/certs/server.key"); err != nil {
		log.Fatalf("(HTTPS) error listening to port: %v", err)
	}

}