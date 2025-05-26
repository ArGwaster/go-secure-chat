package goSecureChat

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
)

func ServerMode() {
	priv, pub := generateRSAKeys()

	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Println("🟢 Serveur en attente sur :1337")

	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Println("🔗 Client connecté.")

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}
	writer.WriteString(base64.StdEncoding.EncodeToString(pubBytes) + "\n")
	writer.Flush()

	encKeyB64, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("Erreur lecture clé AES chiffrée :", err)
	}
	encKey, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(encKeyB64))

	sessionKey := decryptSessionKey(priv, encKey)
	fmt.Println("🔐 Session sécurisée établie.")

	go readLoop(reader, sessionKey)
	writeLoop(writer, sessionKey)
}
