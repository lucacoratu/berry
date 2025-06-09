package main

import "blueberry/internal/server"

func main() {
	bServer := server.BlueberryServer{}
	err := bServer.Init()
	if err != nil {
		return
	}
	bServer.Run()
}
