package main

import (
	"crypto/x509"
	"flag"

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
	var tpmname = flag.String("tpm", "/dev/tpm0", "The path to the TPM device to use")
	rw, err := tpm2.OpenTPM(*tpmname)
	if err != nil {
		println("Connection to TPM could not be established: %s", err)
	}

	defer rw.Close()
	parentHandle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, pcrSelection7, "", "\x01\x02\x03\x04", defaultKeyParams)
	if err != nil {
		println("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rw, parentHandle)

	privateBlob, _, _, _, _, err := tpm2.CreateKey(rw, parentHandle, pcrSelection7, "", "\x01\x02\x03\x04", defaultKeyParams)
	if err != nil {
		println("CreateKey failed: %s", err)
	}

	println("steht hier etwas interessantes: ", string(privateBlob))
	privKey, _ := x509.ParsePKCS1PrivateKey(privateBlob)
	println("Wie sieht es nach dem Encode aus?: ", privKey)
}
