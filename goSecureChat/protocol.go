package goSecureChat

import (
	"encoding/json"
)

// Types de messages du protocole
const (
	TypeHandshake  = "handshake"
	TypeSessionKey = "session_key"
	TypeMessage    = "message"
	TypeError      = "error"
)

// Structure générique pour tous les messages
type ProtocolMessage struct {
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
	Data    string `json:"data"`
}

// Structure spécifique pour les messages chiffrés
type EncryptedMessage struct {
	Type       string `json:"type"`
	Version    string `json:"version,omitempty"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
}

// Crée un message de handshake (clé publique)
func createHandshakeMessage(publicKeyB64 string) ([]byte, error) {
	msg := ProtocolMessage{
		Type:    TypeHandshake,
		Version: "1.0",
		Data:    publicKeyB64,
	}
	return json.Marshal(msg)
}

// Crée un message de clé de session
func createSessionKeyMessage(sessionKeyB64 string) ([]byte, error) {
	msg := ProtocolMessage{
		Type:    TypeSessionKey,
		Version: "1.0",
		Data:    sessionKeyB64,
	}
	return json.Marshal(msg)
}

// Crée un message chiffré
func createEncryptedMessage(ciphertextB64, nonceB64 string) ([]byte, error) {
	msg := EncryptedMessage{
		Type:       TypeMessage,
		Version:    "1.0",
		Ciphertext: ciphertextB64,
		Nonce:      nonceB64,
	}
	return json.Marshal(msg)
}

// Crée un message d'erreur
func createErrorMessage(errorMsg string) ([]byte, error) {
	msg := ProtocolMessage{
		Type: TypeError,
		Data: errorMsg,
	}
	return json.Marshal(msg)
}

// Parse un message JSON générique
func parseProtocolMessage(jsonData []byte) (*ProtocolMessage, error) {
	var msg ProtocolMessage
	err := json.Unmarshal(jsonData, &msg)
	return &msg, err
}

// Parse un message chiffré
func parseEncryptedMessage(jsonData []byte) (*EncryptedMessage, error) {
	var msg EncryptedMessage
	err := json.Unmarshal(jsonData, &msg)
	return &msg, err
}
