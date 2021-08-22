package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	base "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-attestation/attest"
	jose "gopkg.in/square/go-jose.v2"
)

var globNonce = ""
var globAk = attest.AK{}
var globTPM = attest.TPM{}
var globPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)

type dummyNonceSource struct{}

type Identifier struct {
	Type  string `json:"type"`
	Value string
}

func newAccount(signMeUpURL string) (account_url string, order_list_url string) {
	var signerOpts = jose.SignerOptions{NonceSource: dummyNonceSource{}}
	signerOpts.WithHeader("jwk", jose.JSONWebKey{Key: globPrivateKey.Public()})
	signerOpts.WithHeader("url", signMeUpURL)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: globPrivateKey}, &signerOpts)
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

	req, err := http.NewRequest("POST", signMeUpURL, strings.NewReader(serialized))
	req.Header.Add("Content-Type", "application/jose+json")

	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	m := make(map[string]json.RawMessage)
	err = json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	println("newAccount: Account created!")
	println("")
	globNonce = resp.Header.Get("Replay-Nonce")
	return resp.Header.Get("Location"), trimQuote(string(m["orders"]))
}

func newCertificate(account_url string, request_url string) (auth_order_url string, authorizations_url string, finalizeURL string) {
	EkValue, AkValue, tpmm := getAttestAndEndorseKey()
	globAk = AkValue
	globTPM = tpmm
	akBytes, err := AkValue.Marshal()

	testinator := []Identifier{{Type: "ek", Value: string(akBytes) + EkValue}}
	payload := map[string]interface{}{"identifiers": testinator, "notBefore": "2021-08-01T00:04:00+04:00", "notAfter": "2021-08-08T00:04:00+04:00"}
	byts, _ := json.Marshal(payload)

	body, resp := sendRequest(account_url, request_url, byts)
	println("newCertificate: New Certificate requested!")
	println("")

	m := make(map[string]json.RawMessage)
	err = json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	finalizeURL = string(m["finalize"])
	z := string(m["authorizations"])
	pos := strings.Index(z, "https:")
	z = z[pos:]
	pos = strings.Index(z, "\"")
	z = z[:pos]
	return resp.Header.Get("Location"), z, trimQuote(finalizeURL)

}

func authChallenge(auth_order_url string, authorization_url string) (secret string, answerUrl string, dns string) {
	// GET as POST request

	byts := []byte{}
	body, _ := sendRequest(auth_order_url, authorization_url, byts)
	println("authChallenge: GET-as-POST request to retreive challange details")
	println("")

	m := make(map[string]json.RawMessage)
	err := json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	return extractUrlSecretDNS(m)
}

func authChallengeAnswer(auth_order_url string, answer_url string, secret string) {
	payload := map[string]interface{}{"status": "valid", "secret": secret}
	byts, _ := json.Marshal(payload)

	sendRequest(auth_order_url, answer_url, byts)
	println("authChallengeAnswer: Challenge answer was send!")
	println("")

}

func makeCSRRequest(auth_order_url string, dns string, finalizeURL string) {
	payload := map[string]interface{}{"csr": teeeestcreateCSR(dns)}
	byts, _ := json.Marshal(payload)

	sendRequest(auth_order_url, finalizeURL, byts)
	println("makeCSRRequest: CSR Request send!")
	println("")
}

func getCertificate(account_url string) (order_url string) {
	// GET as POST request
	byts := []byte{}

	body, _ := sendRequest(account_url, account_url, byts)
	println("getCertificate: GET-as-POST request for the Certificate!")
	println("")

	m := make(map[string]json.RawMessage)
	err := json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	return trimQuote(string(m["orders"]))
}

func downloadCertificate(account_url string, order_url string) (new_order_url string) {
	// GET as POST request
	byts := []byte{}

	body, _ := sendRequest(account_url, order_url, byts)
	println("downloadCertificate: get Certificate URL")
	println("")

	m := make(map[string]json.RawMessage)
	err := json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	url := string(m["orders"])
	pos := strings.Index(url, "\"")
	poss := strings.Index(url, "]")
	url = url[pos+1 : poss-5]
	return url

}

func makeCertificate(account_url string, order_url string) (certificate_url string) {
	// GET as POST request
	byts := []byte{}

	body, _ := sendRequest(account_url, order_url, byts)
	println("downloadCertificate: Get URL")
	println("")

	m := make(map[string]json.RawMessage)
	err := json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}

	return trimQuote(string(m["certificate"]))

}

func requestCertificate(account_url string, certificate_url string) {
	// GET as POST request
	byts := []byte{}

	body, _ := sendRequest(account_url, certificate_url, byts)
	println("GET as POST request to retreive Certificate")
	println("")

	err := ioutil.WriteFile("Certificate", body, 0644)
	if err != nil {
		println("could not write Certificate: ", err.Error())
	}
	//TODO in den TPM schreiben
}

func checkIfStatusValid(auth_order_url string, authorization_url string) (valid bool) {
	// GET as POST request

	byts := []byte{}
	body, _ := sendRequest(auth_order_url, authorization_url, byts)
	println("authChallenge: GET-as-POST request to retreive challange details")
	println("")

	m := make(map[string]json.RawMessage)
	err := json.Unmarshal(body, &m)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	println("Value ist :", string(m["status"]))
	return string(m["status"]) == "\"valid\""
}

func sendRequest(kid string, url string, byts []byte) (body []byte, resp *http.Response) {
	var signerOpts = jose.SignerOptions{NonceSource: dummyNonceSource{}}
	signerOpts.WithHeader("kid", kid)
	signerOpts.WithHeader("url", url)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: globPrivateKey}, &signerOpts)
	if err != nil {
		panic(err)
	}

	object, err := signer.Sign(byts)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()

	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = true
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", url, strings.NewReader(serialized))
	req.Header.Add("Content-Type", "application/jose+json")

	resp, err = client.Do(req)
	if err != nil {
		println(err.Error())
		panic(err)
	}
	defer resp.Body.Close()
	println("HTTP result status: ", resp.Status)
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		panic(err)
	}

	globNonce = resp.Header.Get("Replay-Nonce")
	return body, resp
}

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func createCSR(dns string) (csr string) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)

	emailAddress := "test@example.com"
	subj := pkix.Name{
		CommonName:         dns,
		Country:            []string{"AU"},
		Province:           []string{"Some-State"},
		Locality:           []string{"MyCity"},
		Organization:       []string{"Company Ltd"},
		OrganizationalUnit: []string{"IT"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		DNSNames:           []string{dns},
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	v2 := base64.RawURLEncoding.EncodeToString(csrBytes)
	return v2
}

func extractUrlSecretDNS(m map[string]json.RawMessage) (secret string, answerUrl string, dns string) {
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

	pos = strings.Index(ois[6], "\"DNS\":")
	poss = strings.Index(ois[6], "}")
	dns = ois[6][pos+8 : poss-8]

	return solveEkSecret(Credentail, Secret), url, trimQuote(dns)
}

func solveEkSecret(Credentail string, Secret string) (secret string) {
	decode := base.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	bcred, _ := decode.DecodeString(Credentail)
	bSecret, _ := decode.DecodeString(Secret)
	cred := attest.EncryptedCredential{Credential: bcred, Secret: bSecret}

	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)

	tes, _ := globAk.Marshal() // attest.AK
	tess, _ := tpm.LoadAK(tes) // *attest.Ak

	bsecret, err := tess.ActivateCredential(tpm, cred)

	if err != nil {
		panic(err)
	}

	return decode.EncodeToString(bsecret)
}

func (n dummyNonceSource) Nonce() (string, error) {
	if globNonce != "" {
		return globNonce, nil
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	res, err := client.Head("https://192.168.1.8:14000/nonce-plz")
	if err != nil {
		panic(err)
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
