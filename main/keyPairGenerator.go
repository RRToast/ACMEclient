package main

import (
	"crypto/x509"

	"github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
)

type fiss struct {
	number int
}

var (
	defaultKeyParams = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.FlagStorageDefault,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 1<<16 + 1,
		},
	}
	pcrSelection7 = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
)

func createPublicPrivateKey() {
	rw, _ := tpm.OpenTPM()
	defer rw.Close()
	parentHandle, _, _ := tpm2.CreatePrimary(rw, tpm2.HandleOwner, pcrSelection7, "", "\x01\x02\x03\x04", defaultKeyParams)
	defer tpm2.FlushContext(rw, parentHandle)

	privateBlob, _, _, _, _, _ := tpm2.CreateKey(rw, parentHandle, pcrSelection7, "", "\x01\x02\x03\x04", defaultKeyParams)

	println("steht hier etwas interessantes: ", string(privateBlob))
	privKey, _ := x509.ParsePKCS1PrivateKey(privateBlob)
	println("Wie sieht es nach dem Encode aus?: ", privKey)
}
