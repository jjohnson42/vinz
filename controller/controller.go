package controller

import (
	"errors"
	"encoding/binary"
	"io"
	"os"
	"net"
	"fmt"
	"vinz/vncconnector"
	"vinz/websockserver"
)

type Controller struct {
	approver string
	clientdir string
	authtoken string
	apilocation string
	wss websockserver.WebSockServer
}

// control request:
// cmdcode - 1 byte - 1: prepare for new unix domain connection
// namelen -uint32
// name
// reply:
// replycode: 1 byte: 1 success
// fnamelen - uint32
// fname
// ff eof

// cmdcode 2: register trusted auth token
// sessionidsz - uint32
// sessionid
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
		// request to make a new unix socket entry point
		// randomize name and notify controller of
		// the name for it's reference'
		binary.Read(conn, binary.BigEndian, &msgsize)
		nodename := make([]byte, msgsize)
		_, err := io.ReadFull(conn, nodename)
		err = binary.Read(conn, binary.BigEndian, &cmdcode)
		if err != nil {
			return err
		}
		vc, err := vncconnector.CreateVncConnector(
			ctl.approver, ctl.clientdir, ctl.authtoken, string(nodename))
		if err != nil {
			return err
		}
		binary.Write(conn, binary.BigEndian, byte(1))
		filenamebytes := []byte(vc.Filename)
		binary.Write(conn, binary.BigEndian, uint32(len(filenamebytes)))
		conn.Write(filenamebytes)
		binary.Write(conn, binary.BigEndian, byte(255))
		go vc.Listen()
	} else {
		return errors.New("Unrecognized command code")
	}
	return nil
}


func CreateController(apilocation string, authtoken string, approver string, clientdir string, websockspec string) (Controller, error) {
	wss := websockserver.CreateWebSockServer()
	go wss.Listen(websockspec)
	return Controller{approver, clientdir, authtoken, apilocation, wss}, nil
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
