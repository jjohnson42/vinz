package main
import (
	"flag"
)
func main() {
	flag.Parse()
	vc := createVncConnector(flag.Args()[0], flag.Args()[1], flag.Args()[2])
	vc.Listen(flag.Args()[3])
}
