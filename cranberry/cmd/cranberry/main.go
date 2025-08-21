package main

import "cranberry/internal/server"

func main() {
	cServer := server.CranberryServer{}
	err := cServer.Init()
	if err != nil {
		return
	}
	cServer.Run()
}
