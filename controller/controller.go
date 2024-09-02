package controller

import (
	"errors"
	"encoding/binary"
	"io"
	"os"
	"net"
	"fmt"
	"vinz/vncconnector"
)

type Controller struct {
	approver string
	clientdir string
	authtoken string
	apilocation string
}

// control request:
// cmdcode - 1 byte - 1: prepare for new unix domain connection
// endpointidlen - uint32
// endpointid
// namelen -uint32
// name

// cmdcode 2: register trusted auth token
// authtokenlen - uint32
// authtoken
func (ctl *Controller) handleControlRequest (conn net.Conn) error {
	defer func() {
		r:= recover()
		if r != nil {
			fmt.Println("Recovered: ", r)
		}
		conn.Close()
	}()
	var cmdcode byte
	var msgsize uint32
	err := binary.Read(conn, binary.BigEndian, &cmdcode)
	if err != nil {
		return err
	}
	if cmdcode == 1 {
		binary.Read(conn, binary.BigEndian, &msgsize)
		endpointid := make([]byte, msgsize)
		io.ReadFull(conn, endpointid)
		binary.Read(conn, binary.BigEndian, &msgsize)
		nodename := make([]byte, msgsize)
		_, err := io.ReadFull(conn, nodename)
		if err != nil {
			return err
		}
		vc := vncconnector.CreateVncConnector(
			string(endpointid), ctl.approver, ctl.clientdir, ctl.authtoken, string(nodename))
		go vc.Listen()
	} else if cmdcode == 2 {  // register trusted peer authtoken
		binary.Read(conn, binary.BigEndian, &msgsize)
		peerauthtoken := make([]byte, msgsize)
		_, err := io.ReadFull(conn, peerauthtoken)
		if err != nil {
			return err
		}
		//TODO: register peer token with websock handler
	} else {
		return errors.New("Unrecognized command code")
	}
	return nil
}


func CreateController(apilocation string, authtoken string, approver string, clientdir string) (Controller, error) {
	return Controller{approver, clientdir, authtoken, apilocation}, nil
}

func (ctl *Controller) Listen() {
	ctlsock, err := net.Listen("unix", ctl.apilocation)
	if err != nil {
		panic(err)
	}
	os.Chmod(ctl.apilocation, 0600)
	for {
		conn, err := ctlsock.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go ctl.handleControlRequest(conn)
	}

}
