package main

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/google/go-attestation/attest"
)

func getAttestAndEndorseKey() (ekS string, akS string) {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		panic(err)
	}

	eks, err := tpm.EKs()
	if err != nil {
		panic(err)
	}

	ek := eks[0]
	if err != nil {
		panic(err)
	}
	// EK
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		panic(err)
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)
	println(string(pubkey_pem))

	// AK
	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	akBytes, err := ak.Marshal()
	println("Hier steht akBytes:", string(akBytes))

	return string(pubkey_pem), string(akBytes)
}
