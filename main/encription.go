package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strings"

	"gopkg.in/square/go-jose.v2"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	localCertFile = "Downloads/root20062021"
)

// Quelle: https://pkg.go.dev/gopkg.in/square/go-jose.v2
// Quelle: https://stackoverflow.com/questions/24455147/how-do-i-send-a-json-string-in-a-post-request-in-go
// Quelle: https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
// https://golangcode.com/download-a-file-from-a-url/
// https://github.com/minio/minio-go/issues/1019

type Header struct {
	// The algorithm used for signature.
	Algorithm string `json:"alg"`

	// Represents the token type.
	Typ string `json:"typ"` //todo: <- was ist das?

	// The optional hint of which key is being used.
	KeyID string `json:"kid,omitempty"`
}

func combine(nonce string) {
	println("Encryption start")

	addNewTrusedCert()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	println(privateKey)
	// Instantiate a signer using RSASSA-PSS (SHA512) with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: privateKey}, nil)
	value := jose.JSONWebKey{Key: privateKey.Public()}
	testHeader := jose.Header{JSONWebKey: &value, Algorithm: string(jose.PS512), Nonce: nonce, ExtraHeaders: map[jose.HeaderKey]interface{}{"url": "https://localhost:14000/sign-me-up"}}
	// Herr Schreck fragen ...

	if err != nil {
		panic(err)
	}
	println("Signer:%v", signer)

	// Sign a sample payload. Calling the signer returns a protected JWS object,
	// which can then be serialized for output afterwards. An error would
	// indicate a problem in an underlying cryptographic primitive.
	var payload = []byte("Lorem ipsum dolor sit amet")
	object, err := signer.Sign(payload)
	object2, err := signer.Options(jose.SignerOptions.with)
	if err != nil {
		panic(err)
	}

	// Serialize the encrypted object using the full serialization format.
	// Alternatively you can also use the compact format here by calling
	// object.CompactSerialize() instead.
	serialized := object.FullSerialize()
	println("Payload: ", serialized)
	// ----------------------------------------------------------------------------------------------------------------------------
	/* 	fileURL := "https://localhost:15000/roots/0"
	   	error := DownloadFile("0", fileURL)
	   	   	if error != nil {
	   	   		panic(err)
	   	   	} */
	/*insecure := flag.Bool("insecure-ssl", false, "Accept/Ignore all server SSL certificates")
	flag.Parse()
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	certs, err := ioutil.ReadFile(localCertFile)
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", localCertFile, err)
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("No certs appended, using system certs only")
	}

	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: *insecure,
		RootCAs:            rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr} */
	// ----------------------------------------------------------------------------------------------------------------------------
	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = true
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://localhost:14000/sign-me-up", strings.NewReader(serialized))
	req.Header.Add("Content-Type", "application/jose+json")
	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	defer resp.Body.Close()
	println("HTTP result status: ", resp.Status)
	println("HTTP result body: ", resp.Body)

	/* 	// Parse the serialized, protected JWS object. An error would indicate that
	   	// the given input did not represent a valid message.
	   	object, err = jose.ParseSigned(serialized)
	   	if err != nil {
	   		panic(err)
	   	}
	   	println("Object:%v", object)

	   	// Now we can verify the signature on the payload. An error here would
	   	// indicate that the message failed to verify, e.g. because the signature was
	   	// broken or the message was tampered with.
	   	output, err := object.Verify(&privateKey.PublicKey)
	   	if err != nil {
	   		panic(err)
	   	}
	   	println("Output:%v", string(output)) */
	println("Encription finished")
}

func addNewTrusedCert() {
}

func DownloadFile(filepath string, url string) error {
	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = true
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}
	// Get the data

	test := ""
	haus := strings.NewReader(test)
	req, err := http.NewRequest("GET", url, haus)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	println("HTTP result status: ", resp.Status)
	println("HTTP result body: ", resp.Body)
	println("haus = ", haus)
	println("test = ", test)
	/* 	resp, err := http.Get(url)
	   	tlsConfig.do
	   	if err != nil {
	   		if err.Error() != "Get \"https://localhost:15000/roots/0\": x509: certificate signed by unknown authority" {
	   			return err
	   		}
	   	} */

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	println("Wir sind hier")

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err

}
