package main

import (
	"flag"
	"os"
)

func main() {
	flag.Parse()
	endpointid := flag.Args()[0]
	sessionpath := flag.Args()[1]
	clientdir := flag.Args()[2]
	authtoken := os.Getenv("VINZ_TOKEN")
	vc := CreateVncConnector(endpointid, sessionpath, clientdir, authtoken)
	vc.Listen()
}
