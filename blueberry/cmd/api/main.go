package main

import "blueberry/internal/server"

func main() {
	proxyServer := server.AgentServer{}
	err := proxyServer.Init()
	if err != nil {
		return
	}
	proxyServer.Run()
}
