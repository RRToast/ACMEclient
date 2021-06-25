package main

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	jose "gopkg.in/square/go-jose.v2"
)

type dummyNonceSource struct{}

func (n dummyNonceSource) Nonce() (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	res, err := client.Head("https://localhost:14000/nonce-plz")
	if err != nil {
		panic(err)
	}
	ua := res.Header.Get("Replay-Nonce")
	return ua, nil
}

func newAccount(privateKey *rsa.PrivateKey) (order_url string) {
	var signerOpts = jose.SignerOptions{NonceSource: dummyNonceSource{}}
	signerOpts.WithHeader("jwk", jose.JSONWebKey{Key: privateKey.Public()})
	signerOpts.WithHeader("url", "https://localhost:14000/sign-me-up")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &signerOpts)
	if err != nil {
		panic(err)
	}
	println("test")

	var testor [1]string
	testor[0] = "mailto:test.test@test.de"
	payload := map[string]interface{}{"termsOfServiceAgreed": true, "contact": testor}
	byts, _ := json.Marshal(payload)
	fmt.Println(string(byts))
	signer.Options()
	object, err := signer.Sign(byts)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()

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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	println("HTTP result body: ", string(body))
	m := make(map[string]json.RawMessage)
	err = json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	println("Account created")
	return string(m["orders"])
}

type identifier struct {
	key   string
	value string
}

func newCertificate(privateKey *rsa.PrivateKey, order_url string) {
	var signerOpts = jose.SignerOptions{NonceSource: dummyNonceSource{}}
	println(order_url)
	signerOpts.WithHeader("kid", order_url)
	signerOpts.WithHeader("url", "https://localhost:14000/order-plz")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &signerOpts)
	if err != nil {
		panic(err)
	}
	testinator := map[string]string{"type": "dns", "value": "www.example.org"}
	payload := map[string]interface{}{"identifiers": testinator, "notBefore": "2021-08-01T00:04:00+04:00", "notAfter": "2021-08-08T00:04:00+04:00"}
	byts, _ := json.Marshal(payload)
	fmt.Println(string(byts))
	signer.Options()
	object, err := signer.Sign(byts)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()
	println("Payload: ", serialized)

	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = true
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://localhost:14000/order-plz", strings.NewReader(serialized))
	req.Header.Add("Content-Type", "application/jose+json")

	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	defer resp.Body.Close()
	println("HTTP result status: ", resp.Status)
	body, err := io.ReadAll(resp.Body)
	println("HTTP result body: ", string(body))

}
