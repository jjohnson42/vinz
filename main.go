package main

import (
	"os/signal"
	"syscall"
	"fmt"
	"flag"
	"os"
	//"vinz/vncconnector"
	"vinz/controller"
)

func main() {
	clientdir := flag.String("d", "", "Directory to place UNIX client facing sockets for VNC")
	approver := flag.String("a", "", "Approver socket used to arbitrate new client connection attempts")
	wsockpath := flag.String("w", "", "Websocket listen specification")
	location := flag.String("c", "", "Control socket path to listen for commands")

	flag.Parse()
	//endpointid := flag.Args()[0]
	authtoken := os.Getenv("VINZ_TOKEN")
	ctl, err := controller.CreateController(*location, authtoken, *approver, *clientdir, *wsockpath)
	if err != nil {
		panic(err)
	}
	cleanupchan := make(chan os.Signal, 1)
	signal.Notify(cleanupchan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-cleanupchan
		os.Remove(*location)
		clientsocks, _ := os.ReadDir(*clientdir)
		for _, item := range clientsocks {
			os.Remove(fmt.Sprintf("%s/%s", *clientdir, item.Name()))
		}
		os.Exit(0)
	}()
	ctl.Listen()
	//vc := CreateVncConnector(endpointid, sessionpath, clientdir, authtoken)
	//vc.Listen()
}
