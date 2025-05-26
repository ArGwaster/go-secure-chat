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

	// 1. Envoyer la clé publique via JSON
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubBytes)

	handshakeMsg, err := createHandshakeMessage(pubB64)
	if err != nil {
		log.Fatal(err)
	}
	writer.WriteString(string(handshakeMsg) + "\n")
	writer.Flush()

	// 2. Recevoir la clé de session chiffrée via JSON
	jsonLine, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("Erreur lecture message JSON :", err)
	}

	msg, err := parseProtocolMessage([]byte(strings.TrimSpace(jsonLine)))
	if err != nil {
		log.Fatal("Erreur parsing JSON :", err)
	}

	if msg.Type != TypeSessionKey {
		log.Fatal("Type de message inattendu :", msg.Type)
	}

	encKey, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		log.Fatal("Erreur décodage clé de session :", err)
	}

	sessionKey := decryptSessionKey(priv, encKey)
	fmt.Println("🔐 Session sécurisée établie.")

	go readLoopJSON(reader, sessionKey)
	writeLoopJSON(writer, sessionKey)
}
