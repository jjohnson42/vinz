package vncconnector

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/gorilla/websocket"
)

type VncConnector struct {
	sessionpath string
	clientdir string
	authtoken string
	nodename []byte
	Filename string
	targurl string
}

func CreateVncConnector(sessionpath string, clientdir string, authtoken string, nodename string) (*VncConnector, error) {
	sessfilenamebytes := make([]byte, 33)
	_, err := rand.Read(sessfilenamebytes)
	if err != nil {
		return nil, err
	}
	sessfilename := base64.URLEncoding.EncodeToString((sessfilenamebytes))
	vc := VncConnector{sessionpath, clientdir, authtoken, []byte(nodename), sessfilename, ""}
	return &vc, nil
}

func relayPlainToWebsock(src net.Conn, dst *websocket.Conn) {
	inbuffer := make([]byte, 65536)
	for {
		mlen, err := src.Read(inbuffer)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = dst.WriteMessage(websocket.BinaryMessage, inbuffer[:mlen])
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func relayWebSockToWebsock(src *websocket.Conn, dst *websocket.Conn) {
	for {
		typ, msg, err := src.ReadMessage()
		if err != nil {
			fmt.Println(err)
			return
		}
		err = dst.WriteMessage(typ, msg)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}
func (vc *VncConnector) relayToClient(toclient chan []byte, wserver *websocket.Conn) {
	// calling function is expected to handle details of plain v. websock client
	defer close(toclient)
	pktnum := 0
	customnamesupport := true
	var securitymsg []byte
	securitymsg = make([]byte, 2)
	securitymsg[0] = 1
	securitymsg[1] = 1
	for {
		_, msg, err := wserver.ReadMessage()
		if err != nil {
			fmt.Println(err)
			return
		}
		if pktnum < 4 && customnamesupport {
			if pktnum == 0 {
				if !bytes.Equal(msg, []byte("RFB 003.008\n")) {
					customnamesupport = false
				}
			} else if pktnum == 1 {
				if !bytes.Equal(msg, securitymsg) {
					customnamesupport = false
				}
			} else if pktnum == 3 {
				// Let's interject requested nodename
				// The default name is generally useless, particularly when dealing
				// with multiple windows and wanting to do title search'
				if len(msg) > 24 {
					newmsg := make([]byte, 24 + len(vc.nodename) + 4)

					copy(newmsg[:20], msg[:20])
					binary.BigEndian.PutUint32(newmsg[20:], uint32(4 + len(vc.nodename)))
					copy(newmsg[24:], vc.nodename)
					copy(newmsg[24+len(vc.nodename):], " KVM")
					msg = newmsg
				}
			}
			pktnum += 1
		}
		toclient <- msg
	}
}

func (vc VncConnector) Listen() {
	location := fmt.Sprintf("%s/%s", vc.clientdir, vc.Filename)
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
// 	byte 1: reqtype, 1 for now, request for remote video data
// 	uint32: length of the authentitacion toke
//	the service authentication token
//	uint32: length of the nodename
// 	nodename: the endpointid identifying the client
//	byte:  the sort of client authentication (1 = so_peercred, 2 = sessionid/xsrftoken combo from webui)
//	authentication payload (uid or TLV of sessionid/xsrftoken)
//      0xff - terminator

//reply:
//	retver byte: 1 == normal, 0 == close, 2 == redirect
//	host length
//	host header value
//	sessionid length
//	sessionid token value
//	xsrf length
//	xsrf token value
//	uint32 fingerprint length (length determines if sha256, sha384, or sha512)
//	fingerprint in raw bytes
//	url len
//	wss url (this might be /kvm/0, or it could be a vinz url)
//      0xff - terminator

func (vc *VncConnector) Connect(vnclient net.Conn, uid uint32) error {
	defer vnclient.Close()
	var msgsz uint32
	var rplytype byte
	conn, err := net.Dial("unix", vc.sessionpath)
	if err != nil {
		return err
	}
	defer conn.Close()
	bnodename := []byte(vc.nodename)
	bauthtoken := []byte(vc.authtoken)
	binary.Write(conn, binary.BigEndian, rqver)
	binary.Write(conn, binary.BigEndian, uint32(len(bauthtoken)))
	conn.Write(bauthtoken)
	binary.Write(conn, binary.BigEndian, uint32(len((bnodename))))
	conn.Write(bnodename)
	binary.Write(conn, binary.BigEndian, unix_id_type)
	binary.Write(conn, binary.BigEndian, uid)
	binary.Write(conn, binary.BigEndian, byte(255))
	binary.Read(conn, binary.BigEndian, &rplytype)
	if rplytype == 1 {
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
		binary.Read(conn, binary.BigEndian, &msgsz)
		url := make([]byte, msgsz)
		_, err = io.ReadFull(conn, url)
		vc.targurl = string(url)
		err = binary.Read(conn, binary.BigEndian, &rplytype)  // consume 0xff
		if err != nil {
			return err
		}
		vc.connectVncToIkvm(vnclient, fprint, string(sessionid), string(xsrftoken), string(hostname))
		return nil
	} else if rplytype == 2 { // redirect
		binary.Read(conn, binary.BigEndian, &msgsz)
		peervinz := make([]byte, msgsz)  // This should be a full url
		io.ReadFull(conn, peervinz)
		err := errors.New("TODO: implement redirect")
		return err
	} else {
		err := errors.New("Failure getting parameters")
		return  err
	}
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

func (vc *VncConnector) connectVncToIkvm(vncclient net.Conn, fprint []byte, sessionid string, xsrftoken string, target string) error {
	wserver, err := vc.connectToIkvm(fprint, sessionid, xsrftoken, target)
	if err != nil {
		return err
	}
	defer wserver.Close()
	toclient := make(chan []byte)
	go relayPlainToWebsock(vncclient, wserver)
	go vc.relayToClient(toclient, wserver)
	for {
		msg, more := <- toclient
		if !more {
			break
		}
		vncclient.Write(msg)
	}
	return nil
}

func (vc *VncConnector) connectToIkvm(fprint []byte, sessionid string, xsrftoken string, target string) (*websocket.Conn, error) {
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
	urlhost = strings.Replace(urlhost, "%", "%25", 1)
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
	var err error
	dialer.Jar, err = cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	dialer.Subprotocols = make([]string, 0)
	dialer.Subprotocols = append(dialer.Subprotocols, xsrftoken)
	headers := http.Header{}
	headers.Add("Host", hostname)
	targurl := fmt.Sprintf("wss://%s%s", urlhost, vc.targurl)
	SetCookies(targurl, sessionid, xsrftoken, dialer.Jar)
	wserver, rsp, err := dialer.Dial(targurl, headers)
	if err != nil {
		fmt.Println(err)
		fmt.Println(rsp)
		return nil, err
	}
	return wserver, nil
}
