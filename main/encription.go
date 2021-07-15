package main

import (
	"crypto/rsa"
	"crypto/tls"
	base "encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-attestation/attest"
	jose "gopkg.in/square/go-jose.v2"
)

var globNonce = ""
var globAk = attest.AK{}
var globTPM = attest.TPM{}
var globFirstIteration = true

type dummyNonceSource struct{}

type Identifier struct {
	Type  string `json:"type"`
	Value string
}

func newAccount(privateKey *rsa.PrivateKey) (order_url string) {
	var signerOpts = jose.SignerOptions{NonceSource: dummyNonceSource{}}
	signerOpts.WithHeader("jwk", jose.JSONWebKey{Key: privateKey.Public()})
	signerOpts.WithHeader("url", "https://192.168.1.5:14000/sign-me-up")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &signerOpts)
	if err != nil {
		panic(err)
	}

	var testor [1]string
	testor[0] = "mailto:globNonce.globNonce@globNonce.de"
	payload := map[string]interface{}{"termsOfServiceAgreed": true, "contact": testor}
	byts, _ := json.Marshal(payload)
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

	req, err := http.NewRequest("POST", "https://192.168.1.5:14000/sign-me-up", strings.NewReader(serialized))
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
	// println("HTTP result header:", string(resp.Header.Get("Location")))
	// println("HTTP result body: ", string(body))
	m := make(map[string]json.RawMessage)
	err = json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	println("Account created")
	println("")
	globNonce = resp.Header.Get("Replay-Nonce")
	return resp.Header.Get("Location")
}

func newCertificate(privateKey *rsa.PrivateKey, order_url string) (auth_order_url string, authorizations_url string) {
	var signerOpts = jose.SignerOptions{NonceSource: dummyNonceSource{}}
	signerOpts.WithHeader("kid", order_url)
	signerOpts.WithHeader("url", "https://192.168.1.5:14000/order-plz")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &signerOpts)
	if err != nil {
		panic(err)
	}

	EkValue, AkValue, tpmm := getAttestAndEndorseKey()
	globAk = AkValue
	globTPM = tpmm
	akBytes, err := AkValue.Marshal()

	testinator := []Identifier{{Type: "ek", Value: string(akBytes) + EkValue}}
	payload := map[string]interface{}{"identifiers": testinator, "notBefore": "2021-08-01T00:04:00+04:00", "notAfter": "2021-08-08T00:04:00+04:00"}
	byts, _ := json.Marshal(payload)
	signer.Options()
	object, err := signer.Sign(byts)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()
	// println("Payload: ", serialized)

	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = true
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://192.168.1.5:14000/order-plz", strings.NewReader(serialized))
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
	// println("HTTP result header:", string(resp.Header.Get("Location")))
	// println("HTTP result body: ", string(body))
	m := make(map[string]json.RawMessage)
	err = json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	println("NewCertificate requested")
	println("")
	globNonce = resp.Header.Get("Replay-Nonce")
	z := string(m["authorizations"])
	pos := strings.Index(z, "https:")
	z = z[pos:]
	pos = strings.Index(z, "\"")
	z = z[:pos]
	println(z)
	return resp.Header.Get("Location"), z

}

func authChallenge(privateKey *rsa.PrivateKey, auth_order_url string, authorization_url string) (secret string, answerUrl string) {
	// GET as POST request
	println("auth_order_url:", auth_order_url)
	println("authorization_url:", authorization_url)
	var signerOpts = jose.SignerOptions{NonceSource: dummyNonceSource{}}
	signerOpts.WithHeader("kid", auth_order_url)
	signerOpts.WithHeader("url", authorization_url)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &signerOpts)
	if err != nil {
		panic(err)
	}

	byts := []byte{}
	object, err := signer.Sign(byts)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()
	// println("Payload: ", serialized)

	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = true
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", authorization_url, strings.NewReader(serialized))
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
	println("HTTP result header:", string(resp.Header.Get("Location")))
	// println("HTTP result body: ", string(body))
	println("")
	m := make(map[string]json.RawMessage)
	err = json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	globNonce = resp.Header.Get("Replay-Nonce")
	if globFirstIteration {
		return extractUrlAndSecret(m)
	} else {
		return "", ""
	}

}

func authChallengeAnswer(privateKey *rsa.PrivateKey, auth_order_url string, answer_url string, secret string) {
	println("auth_order_url:", auth_order_url)
	println("authorization_url:", answer_url)
	var signerOpts = jose.SignerOptions{NonceSource: dummyNonceSource{}}
	signerOpts.WithHeader("kid", auth_order_url)
	signerOpts.WithHeader("url", answer_url)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &signerOpts)
	if err != nil {
		panic(err)
	}

	payload := map[string]interface{}{"status": "valid", "secret": secret}
	byts, _ := json.Marshal(payload)
	signer.Options()
	object, err := signer.Sign(byts)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()
	// println("Payload: ", serialized)

	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = true
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", answer_url, strings.NewReader(serialized))
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
	println("HTTP result header:", string(resp.Header.Get("Location")))
	println("HTTP result body: ", string(body))
	println("")
	m := make(map[string]json.RawMessage)
	err = json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}

	globNonce = resp.Header.Get("Replay-Nonce")

}

func extractUrlAndSecret(m map[string]json.RawMessage) (secret string, answerUrl string) {
	globFirstIteration = false
	ois := strings.Split(string(m["challenges"]), ",")

	pos := strings.Index(ois[1], "\"url\":")
	url := ois[1][pos+8 : len(ois[1])-1]

	pos = strings.Index(ois[2], "\"token\":")
	//token := ois[2][pos+10 : len(ois[2])-1]

	pos = strings.Index(ois[4], "\"Credential\":")
	Credentail := ois[4][pos+15 : len(ois[4])-1]

	pos = strings.Index(ois[5], "\"Secret\":")
	poss := strings.Index(ois[5], "}")
	Secret := ois[5][pos+11 : poss-4]

	/* 	println("Meine URL: ", url)
	   	println("Mein Token: ", token)
	   	println("Mein Credentail:", Credentail)
	   	println("Mein Secret:", Secret) */

	return solveEkSecret(Credentail, Secret), url
}

func solveEkSecret(Credentail string, Secret string) (secret string) {
	decode := base.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	bcred, _ := decode.DecodeString(Credentail)
	bSecret, _ := decode.DecodeString(Secret)
	cred := attest.EncryptedCredential{Credential: bcred, Secret: bSecret}

	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)

	tes, _ := globAk.Marshal()
	tess, _ := tpm.LoadAK(tes)

	bsecret, err := tess.ActivateCredential(tpm, cred)

	if err != nil {
		panic(err)
	}

	return decode.EncodeToString(bsecret)
}

func (n dummyNonceSource) Nonce() (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	res, err := client.Head("https://192.168.1.5:14000/nonce-plz")
	if err != nil {
		panic(err)
	}
	if globNonce != "" {
		return globNonce, nil
	}
	ua := res.Header.Get("Replay-Nonce")
	return ua, nil
}

func trimQuote(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s
}
