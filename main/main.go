package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

type Message struct {
	alg   string
	jwk   string
	nonce string
	url   string
}

func main() {
	println("start")

	testmode := false
	if testmode {
		//teeeest()
	} else {
		account_url, order_list_url := newAccount("https://192.168.1.2:14000/sign-me-up")                       // Create Account
		_, authorization_url, finalizeURL := newCertificate("https://192.168.1.2:14000/order-plz", account_url) // Create Order
		secret, answer_url, dns := authChallenge(account_url, authorization_url)                                // Get(Request) Challenge
		authChallengeAnswer(account_url, answer_url, secret)                                                    // answer Challenge
		// time.Sleep(10 * time.Second)                                                                            // rest to let server update order Status
		waitForServerToUpdateStatus(account_url, authorization_url)
		//TODO pooling verwenden
		makeCSRRequest(account_url, dns, finalizeURL)                       // request a Certifikat using CSR
		new_order_url := downloadCertificate(order_list_url, account_url)   // Get(Request) the order Element
		certificate_url := downloadCertificate2(new_order_url, account_url) // Get(Request) extract the Certificate URL from Order
		downloadCertificate3(certificate_url, account_url)                  // Get(Request) Certifikate
	}
}

func waitForServerToUpdateStatus(account_url string, authorization_url string) {
	valid := false
	for !valid {
		valid = checkIfStatusValid(account_url, authorization_url)
		time.Sleep(2 * time.Second)
	}
}

func getNonce() string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	res, err := client.Head("https://192.168.1.2:14000/nonce-plz")
	if err != nil {
		panic(err)
	}
	ua := res.Header.Get("Replay-Nonce")
	return ua
}
