package main

import (
	"os"
	"os/exec"
)

/*
#!/bin/sh
cd tpm2-tss-engine/
tpm2tss-genkey -a rsa scriptKey.tss
openssl req -new -x509 -engine tpm2tss -key scriptKey.tss -keyform engine -out scriptcsr.csr
rm scriptKey.tss
mv scriptcsr.csr /home/pi
*/

func readCSRFromFile() {
	cmdHome := exec.Command("cd", "..")
	err := cmdHome.Run()
	if err != nil {
		println("cd .. Befehl konnte nicht ausgeführt werden", err)
	}

	cmdTpm2Tss := exec.Command("cd", "tpm2-tss-engine/")
	err = cmdTpm2Tss.Run()
	if err != nil {
		println("cd tpm2-tss-engine/ Befehl konnte nicht ausgeführt werden", err)
	}

	cmdGenkey := exec.Command("tpm2tss-genkey", "-a", "rsa", "scriptKey.tss")
	err = cmdGenkey.Run()
	if err != nil {
		println("tpm2tss-genkey -a rsa scriptKey.tss Befehl konnte nicht ausgeführt werden", err)
	}

	cmdCreateCSR := exec.Command("openssl", "req", "-new", "-x509", "-engine", "tpm2tss", "-key", "scriptKey.tss", "-keyform engine", "-out", "scriptcsr.csr")
	err = cmdCreateCSR.Run()
	if err != nil {
		println("openssl req -new -x509 -engine tpm2tss -key scriptKey.tss -keyform engine -out scriptcsr.csr Befehl konnte nicht ausgeführt werden", err)
	}

	cmdCleanup := exec.Command("rm", "scriptKey.tss")
	err = cmdCleanup.Run()
	if err != nil {
		println("rm scriptKey.tss Befehl konnte nicht ausgeführt werden", err)
	}

	cmdMoveFile := exec.Command("mv", "scriptcsr.csr", "/home/pi/ACMEclinet")
	err = cmdMoveFile.Run()
	if err != nil {
		println("mv scriptcsr.csr /home/pi Befehl konnte nicht ausgeführt werden", err)
	}

	if _, err := os.Stat("scriptcsr.csr"); os.IsNotExist(err) {
		println(" scriptcsr.csr does not exist")
	}

}
