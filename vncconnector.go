package main

import (
	"bytes"
	"encoding/binary"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"syscall"
	"strings"
	"github.com/gorilla/websocket"
)

type VncConnector struct {
	endpointid string
	sessionpath string
	clientdir string
	authtoken string
}

func CreateVncConnector(endpointid string, sessionpath string, clientdir string, authtoken string) VncConnector {
	vc := VncConnector{endpointid, sessionpath, clientdir, authtoken}
	return vc
}

func (vc VncConnector) relayToWebsock(vncclient net.Conn, wserver *websocket.Conn) {
	inbuffer := make([]byte, 65536)
	for {
		mlen, err := vncclient.Read(inbuffer)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = wserver.WriteMessage(websocket.BinaryMessage, inbuffer[:mlen])
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func (wc VncConnector) relayToVncClient(vncclient net.Conn, wserver *websocket.Conn) {
	for {
		_, msg, err := wserver.ReadMessage()
		if err != nil {
			fmt.Println(err)
			return
		}
		vncclient.Write(msg)
	}
}

func (vc VncConnector) Listen() {
	location := fmt.Sprintf("%s/%s", vc.clientdir, vc.endpointid)
	csock, err := net.Listen("unix", location)
	os.Chmod(location, 0666)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := csock.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		uconn := conn.(*net.UnixConn)
		scc, err := uconn.SyscallConn()
		if err != nil {
			fmt.Println(err)
			continue
		}
		var ucred *syscall.Ucred
		scc.Control(func (fdesc uintptr) {
			ucred, err = syscall.GetsockoptUcred(int(fdesc), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
		go vc.Connect(conn, ucred.Uid)
	}
}

const rqver byte = 1
const unix_id_type byte = 1

// Parameter protocol:
// request:
// 	byte 1: rqver, 1 for now
// 	uint32: length of the authentitacion toke
//	the service authentication token
//	uint32: length of the endpointid
// 	endpointid: the endpointid identifying the client
//	byte:  the sort of client authentication (1 = so_peercred, 2 = sessionid/xsrftoken combo from webui)
//	authentication payload (uid or TLV of sessionid/xsrftoken)

//reply:
//	retver byte: 1 == normal, 0 == close
//	host length
//	host header value
//	sessionid length
//	sessionid token value
//	xsrf length
//	xsrf token value
//	uint32 fingerprint length (length determines if sha256, sha384, or sha512)
//	fingerprint in raw bytes

func (vc VncConnector) getParams(uid uint32) ([]byte, string, string, string, error) {
	var msgsz uint32
	var rplytype byte
	conn, err := net.Dial("unix", vc.sessionpath)
	if err != nil {
		return []byte{}, "", "", "", err
	}
	defer conn.Close()
	bendpointid := []byte(vc.endpointid)
	bauthtoken := []byte(vc.authtoken)
	binary.Write(conn, binary.BigEndian, rqver)
	binary.Write(conn, binary.BigEndian, uint32(len(bauthtoken)))
	conn.Write(bauthtoken)
	binary.Write(conn, binary.BigEndian, uint32(len(bendpointid)))
	conn.Write(bendpointid)
	binary.Write(conn, binary.BigEndian, unix_id_type)
	binary.Write(conn, binary.BigEndian, uid)
	binary.Read(conn, binary.BigEndian, &rplytype)
	if rplytype != 1 {
		err := errors.New("Failure getting parameters")
		return  []byte{}, "", "", "", err
	}
	binary.Read(conn, binary.BigEndian, &msgsz)
	hostname := make([]byte, msgsz)
	io.ReadFull(conn, hostname)
	binary.Read(conn, binary.BigEndian, &msgsz)
	sessionid := make([]byte, msgsz)
	io.ReadFull(conn, sessionid)
	binary.Read(conn, binary.BigEndian, &msgsz)
	xsrftoken := make([]byte, msgsz)
	_, err = io.ReadFull(conn, xsrftoken)
	binary.Read(conn, binary.BigEndian, &msgsz)
	fprint := make([]byte, msgsz)
	_, err = io.ReadFull(conn, fprint)
	return fprint, string(sessionid), string(xsrftoken), string(hostname), err
}

func SetCookies(targurl string, sessionid string, xsrftoken string, jar http.CookieJar) error {
	var cookies []*http.Cookie
	targurlparsed, err := url.Parse(strings.Replace(targurl, "wss://", "https://", 1))
	if err != nil {
		fmt.Println(err)
		return err
	}
	cookie := &http.Cookie{
		Name:  "XSRF-TOKEN",
		Value: xsrftoken,
	}
	cookies = append(cookies, cookie)
	cookie = &http.Cookie{
		Name:  "SESSION",
		Value: sessionid,
	}
	cookies = append(cookies, cookie)
	jar.SetCookies(targurlparsed, cookies)
	return nil
}
func (vc VncConnector) Connect(vncclient net.Conn, uid uint32) error {
	// Fetch TLS fingerprint, SESSION, TOKEN, URL, HOST from socket based on UUID
	fprint, sessionid, xsrftoken, target, err := vc.getParams(uid)
	if err != nil {
		return err
	}
	zoneidx := strings.Index(target, "%")
	var hostname string
	if zoneidx >= 0 {
		hostname = target[:zoneidx]
	} else {
		hostname = target[:]
	}
	var urlhost string
	if strings.Contains(target, ":") {
		urlhost = fmt.Sprintf("[%s]", target)
	} else {
		urlhost = target[:]
	}
	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			var currprint []byte
			if len(fprint) == sha512.Size384 {
				currprintsum := sha512.Sum384(rawCerts[0])
				currprint = currprintsum[:]
			} else if len(fprint) == sha256.Size {
				currprintsum := sha256.Sum256(rawCerts[0])
				currprint = currprintsum[:]
			} else {
				return errors.New("Unrecognized fingerprint length")
			}
			if bytes.Equal(currprint, fprint) {
				return nil
			}
			return errors.New("Mismatched fingerprint")
		},
	}
	dialer.Jar, err = cookiejar.New(nil)
	if err != nil {
		return err
	}
	dialer.Subprotocols = make([]string, 0)
	dialer.Subprotocols = append(dialer.Subprotocols, xsrftoken)
	headers := http.Header{}
	headers.Add("Host", hostname)
	targurl := fmt.Sprintf("wss://%s/kvm/0", urlhost)
	SetCookies(targurl, sessionid, xsrftoken, dialer.Jar)
	wserver, rsp, err := dialer.Dial(targurl, headers)
	if err != nil {
		fmt.Println(err)
		fmt.Println(rsp)
		return err
	}
	defer wserver.Close()
	go vc.relayToWebsock(vncclient, wserver)
	vc.relayToVncClient(vncclient, wserver)
	return nil
}

//func listencontrol(ctlpath string) {
//       csock, err := net.Listen("unix", ctlpath)
//      if err != nil {
//             panic(err)
//    }
//   for {
//conn, err := csock.Accept()
//if err != nil {
//        fmt.Println(err)
//        continue
//}
// go handlectlreq(conn)
//  }
//}

func listenvnc(location string) {

}
