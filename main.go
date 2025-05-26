package main

import (
	"fmt"
	"gsc/goSecureChat"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage : go run main.go server|client [ip:port]")
		return
	}

	role := os.Args[1]
	if role == "server" {
		goSecureChat.ServerMode()
	} else if role == "client" {
		if len(os.Args) != 3 {
			fmt.Println("Usage : go run main.go client <ip:port>")
			return
		}
		goSecureChat.ClientMode(os.Args[2])
	} else {
		fmt.Println("Mode inconnu : server|client")
	}
}
