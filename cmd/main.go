package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/slashlight/mitmProxy/pkg/parser"
	"github.com/slashlight/mitmProxy/pkg/storage"
)

func buildPath(url *url.URL) string {
	path := url.Path
	if path == "" {
		path = "/"
	}

	if url.RawQuery != "" {
		path += "?" + url.RawQuery
	}
	return path
}

func parseTarget(url *url.URL) (string, string, error) {
	targetHost := url.Hostname()
	targetPort := url.Port()

	if targetPort == "" {
		targetPort = "80"
	}

	if targetHost == "" {
		return "", "", fmt.Errorf("target host is required")
	}

	return targetHost, targetPort, nil
}

var (
	certCache sync.Map
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	db        *storage.Storage
)

func main() {
	var err error
	caCert, caKey, err = loadCA("ca.crt", "ca.key")
	if err != nil {
		log.Fatal("Error loading CA", err)
	}

	db, err = storage.NewStorage("requests.db")
	if err != nil {
		log.Fatal("Error initializing database:", err)
	}
	defer db.Close()

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("Listening on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Println("Error reading req: ", err)
		return
	}
	defer request.Body.Close()

	if request.Method == http.MethodConnect {
		handleHTTPS(conn, request)
	} else {
		handleHTTP(conn, request)
	}
}

func handleHTTP(conn net.Conn, request *http.Request) {
	targetHost, targetPort, err := parseTarget(request.URL)
	if err != nil {
		fmt.Println("Error parsing target: ", err)
		return
	}

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Println("Error connecting to target: ", err)
		return
	}
	defer targetConn.Close()
	fmt.Println("Connected to ", targetAddr)

	path := buildPath(request.URL)
	request.Header.Del("Proxy-Connection")

	request.Host = targetAddr
	request.URL.Path = path

	parsedReq, err := parser.ParseRequest(request)
	if err != nil {
		fmt.Println("Error parsing request:", err)
	}

	var reqBuff bytes.Buffer
	request.Write(&reqBuff)

	if _, err := targetConn.Write(reqBuff.Bytes()); err != nil {
		fmt.Println("Error writing to target: ", err)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(targetConn), request)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	defer resp.Body.Close()

	parsedResp, err := parser.ParseResponse(resp)
	if err != nil {
		fmt.Println("Error parsing response:", err)
	}

	if parsedReq != nil && parsedResp != nil {
		if err := db.SaveRequestResponse(parsedReq, parsedResp); err != nil {
			fmt.Println("Error saving to database:", err)
		}
	}

	resp.Write(conn)
}

func handleHTTPS(conn net.Conn, request *http.Request) {
	targetConn, err := net.Dial("tcp", request.Host)
	if err != nil {
		fmt.Println("Error connecting to target: ", err)
		return
	}
	defer targetConn.Close()

	connectHost := request.Host

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tlsConf := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := info.ServerName
			if host == "" {
				host = request.URL.Hostname()
			}
			return getCert(host)
		},
	}

	tlsClientConn := tls.Server(conn, tlsConf)
	defer tlsClientConn.Close()

	if err := tlsClientConn.Handshake(); err != nil {
		fmt.Printf("Error handshake with %s with tls: %s\n", request.Host, err)
		return
	}

	tlsTargetConn := tls.Client(targetConn, &tls.Config{
		ServerName: request.URL.Hostname(),
	})
	defer tlsTargetConn.Close()

	if err := tlsTargetConn.Handshake(); err != nil {
		fmt.Println("Error server handshake with tls: ", err)
		return
	}

	reader := bufio.NewReader(tlsClientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Println("Error reading request after CONNECT:", err)
		return
	}
	defer req.Body.Close()

	if req.URL.Host == "" {
		req.URL.Host = connectHost
	}

	targetHost, targetPort, err := parseTarget(req.URL)
	if err != nil {
		fmt.Println("Error parsing target: ", err)
		return
	}

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	path := buildPath(req.URL)

	req.Header.Del("Proxy-Connection")
	req.Host = targetAddr
	req.URL.Path = path

	parsedReq, err := parser.ParseRequest(req)
	if err != nil {
		fmt.Println("Error parsing request:", err)
	}

	var reqBuff bytes.Buffer
	req.Write(&reqBuff)
	if _, err := tlsTargetConn.Write(reqBuff.Bytes()); err != nil {
		fmt.Println("Error writing to target:", err)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsTargetConn), req)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	defer resp.Body.Close()

	parsedResp, err := parser.ParseResponse(resp)
	if err != nil {
		fmt.Println("Error parsing response:", err)
	}

	if parsedReq != nil && parsedResp != nil && parsedReq.Method != "CONNECT" {

		parsedReq.Headers["Host"] = targetHost
		if err := db.SaveRequestResponse(parsedReq, parsedResp); err != nil {
			fmt.Println("Error saving to database:", err)
		}
	}

	resp.Write(tlsClientConn)
}

func loadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key: %v", err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse CA key PEM")
	}

	var key interface{}

	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		return nil, nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("expected RSA private key, got %T", key)
	}

	return cert, rsaKey, nil
}

func getCert(host string) (*tls.Certificate, error) {
	if cert, ok := certCache.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{host},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&certTemplate,
		caCert,
		&privateKey.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	certCache.Store(host, &cert)
	return &cert, nil
}
