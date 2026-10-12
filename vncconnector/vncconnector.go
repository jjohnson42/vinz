package vncconnector

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/des"  // VNC servers that require the relatively useless password
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

type VncConnection struct {
	sessionid string
	hostname string
	fingperprint []byte
	targurl string
	vinztoken string
	sessionpath string
	nodename string
	protocols []string
	cookies map[string]string
	portnum uint16
	passwd string
	swallowauth bool
}

func CreateVncConnection(vinztoken string, sessionpath string, nodename string) VncConnection {
	protocols := []string{}
	cookies := make(map[string]string)
	vconn := VncConnection{"", "", []byte(""), "", vinztoken, sessionpath, nodename, protocols, cookies, 443, "", false}
	return vconn
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

func (vconn *VncConnection) relayPlainToWebsock(src net.Conn, dst *websocket.Conn) {
	inbuffer := make([]byte, 65536)
	defer func() {
		dst.Close()
		src.Close()
	}()
	for {
		mlen, err := src.Read(inbuffer)
		if vconn.swallowauth {
			mlen = 1
			inbuffer[0] = 2
			vconn.swallowauth = false
		}
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

func (vconn *VncConnection) relayWebSockToWebsock(src *websocket.Conn, dst *websocket.Conn) {
	defer func() {
		dst.Close()
		src.Close()
	}()
	for {
		typ, msg, err := src.ReadMessage()
		if vconn.swallowauth {
			msg[0] = 2
			vconn.swallowauth = false
			fmt.Println(msg)
		}
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

func reverseByte(input byte) byte {
	var res byte
	res = 0
	for i := 0; i < 8; i++ {
		res <<= 1
		res |= input & 1
		input >>= 1
	}
	return res
}
func (vconn *VncConnection) relayToClient(toclient chan []byte, wserver *websocket.Conn) {
	// calling function is expected to handle details of plain v. websock client
	defer func() {
		close(toclient)
		wserver.Close()
	}()
	pktnum := 0
	customnamesupport := true
	var securitymsg []byte
	securitymsg = make([]byte, 2)
	securitymsg[0] = 1
	securitymsg[1] = 1
	serverinitpkt := 3
	cryptpkt := 0
	for {
		_, msg, err := wserver.ReadMessage()
		if err != nil {
			fmt.Println(err)
			return
		}
		if pktnum <= serverinitpkt && customnamesupport {
			if pktnum == 0 {
				if !bytes.Equal(msg, []byte("RFB 003.008\n")) {
					customnamesupport = false
				}
			} else if pktnum == 1 {
				if (msg[0] == 1 && msg[1] == 2) {
					serverinitpkt = 4
					cryptpkt = 2
					msg = []byte("\x01\x01")
					vconn.swallowauth = true
				} else if !bytes.Equal(msg, securitymsg) {
					customnamesupport = false
				}
			} else if pktnum == cryptpkt {

				rsp := make([]byte, 16)
				key := []byte(vconn.passwd)
				for i := range key {
					key[i] = reverseByte(key[i])
				}
				nc, err := des.NewCipher(key)
				if err != nil {
					fmt.Println(err)
					return
				}
				nc.Encrypt(rsp[:8], msg[:8])
				nc.Encrypt(rsp[8:], msg[8:])
				wserver.WriteMessage(websocket.BinaryMessage, rsp)
				pktnum += 1
				continue
			} else if pktnum == serverinitpkt {
				// Let's interject requested nodename
				// The default name is generally useless, particularly when dealing
				// with multiple windows and wanting to do title search'
				if len(msg) > 24 {
					newmsg := make([]byte, 24 + len(vconn.nodename) + 4)

					copy(newmsg[:20], msg[:20])
					binary.BigEndian.PutUint32(newmsg[20:], uint32(4 + len(vconn.nodename)))
					copy(newmsg[24:], vconn.nodename)
					copy(newmsg[24+len(vconn.nodename):], " KVM")
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
		go vc.Connect(conn, ucred.Uid)  // Connect with unix auth
	}
}

const rqver byte = 3 // go to new protocol exchange

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
//	retver byte: 1 == normal, 0 == close
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

func (vc *VncConnector) GetWebsockConnection(sessionid string, xsrftoken string) (*VncConnection, error) {
	vconn := CreateVncConnection(vc.authtoken, vc.sessionpath, string(vc.nodename))
	err := vconn.Prepare(2, 0, sessionid, xsrftoken)
	return &vconn, err
	// return vconn.gen_connect(nil, vnclient, 0, sessionid, xsrftoken, 2)
}

func (vconn *VncConnection) WebSockConnect(wsclient *websocket.Conn) error {
	return vconn.Connect(nil, wsclient)
}

func (vc *VncConnector) Connect(vnclient net.Conn, uid uint32) error {
	vconn := CreateVncConnection(vc.authtoken, vc.sessionpath, string(vc.nodename))
	err := vconn.Prepare(1, uid, "", "")
	if err != nil {
		return err
	}
	err = vconn.Connect(vnclient, nil)
	return err
	// return vc.gen_connect(vnclient, nil, uid, "", "", 1)
}

//func (vc *VncConnector) gen_connect(vnclient net.Conn, wsclient *websocket.Conn, uid uint32, sessionid string, xsrftoken string, method byte) error {
func (vconn *VncConnection) Prepare(method byte, uid uint32, clisessionid string, clixsrftoken string) error {
	var msgsz uint32
	var rplytype byte
	var shortlen uint16
	var sessionid []byte
	conn, err := net.Dial("unix", vconn.sessionpath)
	if err != nil {
		return err
	}
	defer conn.Close()
	bnodename := []byte(vconn.nodename)
	bauthtoken := []byte(vconn.vinztoken)
	binary.Write(conn, binary.BigEndian, rqver)
	binary.Write(conn, binary.BigEndian, uint32(len(bauthtoken)))
	conn.Write(bauthtoken)
	binary.Write(conn, binary.BigEndian, uint32(len((bnodename))))
	conn.Write(bnodename)
	binary.Write(conn, binary.BigEndian, method)
	if method == 1 {
		binary.Write(conn, binary.BigEndian, uid)
	} else if method == 2 {
		binary.Write(conn, binary.BigEndian, uint32(len(clisessionid)))
		conn.Write([]byte(clisessionid))
		binary.Write(conn, binary.BigEndian, uint32(len(clixsrftoken)))
		conn.Write([]byte(clixsrftoken))
	}
	binary.Write(conn, binary.BigEndian, byte(255))
	binary.Read(conn, binary.BigEndian, &rplytype)
	if rplytype == 1 || rplytype == 3 {
		binary.Read(conn, binary.BigEndian, &msgsz)
		hostname := make([]byte, msgsz)
		io.ReadFull(conn, hostname)
		binary.Read(conn, binary.BigEndian, &msgsz)
		sessionid = make([]byte, msgsz)
		io.ReadFull(conn, sessionid)
		vconn.sessionid = string(sessionid)
		vconn.hostname = string(hostname)
	}
	if rplytype == 1 {
		binary.Read(conn, binary.BigEndian, &msgsz)
		xsrftoken := make([]byte, msgsz)
		_, err = io.ReadFull(conn, xsrftoken)
		binary.Read(conn, binary.BigEndian, &msgsz)
		fprint := make([]byte, msgsz)
		_, err = io.ReadFull(conn, fprint)
		binary.Read(conn, binary.BigEndian, &msgsz)
		url := make([]byte, msgsz)
		_, err = io.ReadFull(conn, url)
		vconn.targurl = string(url)
		err = binary.Read(conn, binary.BigEndian, &rplytype)  // consume 0xff
		if err != nil {
			return err
		}
		vconn.fingperprint = fprint
		vconn.cookies["XSRF-TOKEN"] = string(xsrftoken)
		vconn.cookies["SESSION"] = string(sessionid)
		vconn.protocols = append(vconn.protocols, string(xsrftoken))
		//vc.connectVncToIkvm(vnclient, wsclient, fprint, string(sessionid), string(xsrftoken), string(hostname))
		return nil
	} else if rplytype == 3 {  // TLV style
		binary.Read(conn, binary.BigEndian, &vconn.portnum)
		for rplytype != 255 {
			binary.Read(conn, binary.BigEndian, &rplytype)
			if rplytype == 255 {
				return nil
			}
			binary.Read(conn, binary.BigEndian, &msgsz)
			if rplytype == 1 { // cookie keyval TLV
				binary.Read(conn, binary.BigEndian, &shortlen)
				cookname := make([]byte, shortlen)
				io.ReadFull(conn, cookname)
				binary.Read(conn, binary.BigEndian, &shortlen)
				cookval := make([]byte, shortlen)
				io.ReadFull(conn, cookval)
				vconn.cookies[string(cookname)] = string(cookval)
			} else if rplytype == 2 {
				protoname := make([]byte, msgsz)
				io.ReadFull(conn, protoname)
				vconn.protocols = append(vconn.protocols, string(protoname))
			} else if rplytype == 3 {
				fprint := make([]byte, msgsz)
				_, err = io.ReadFull(conn, fprint)
				if err != nil {
					return err
				}
				vconn.fingperprint = fprint
			} else if rplytype == 4 {
				url := make([]byte, msgsz)
				_, err = io.ReadFull(conn, url)
				if err != nil {
					return err
				}
				vconn.targurl = string(url)
			} else if rplytype == 5 {
				passwd := make([]byte, msgsz)
				_, err = io.ReadFull(conn, passwd)
				if err != nil {
					return err
				}
				vconn.passwd = string(passwd)
			}
		}
		return nil

	} else {
		err := errors.New("Failure getting parameters")
		return  err
	}
}

func SetCookies(targurl string, cookiemap map[string]string, jar http.CookieJar) error {
	var cookies []*http.Cookie
	targurlparsed, err := url.Parse(strings.Replace(targurl, "wss://", "https://", 1))
	if err != nil {
		fmt.Println(err)
		return err
	}
	var cookie *http.Cookie
	for key, value := range cookiemap {
		cookie = &http.Cookie{
			Name: key,
			Value: value,

		}
		cookies = append(cookies, cookie)
	}
	jar.SetCookies(targurlparsed, cookies)
	return nil
}

func (vconn *VncConnection) Connect(vncclient net.Conn, wsclient *websocket.Conn) error {
	sessionid := vconn.sessionid
	wserver, err := vconn.connectToIkvm()
	if err != nil {
		return err
	}
	defer func() {
		wserver.Close()
		conn, err := net.Dial("unix", vconn.sessionpath)
		if err != nil {
			return
		}
		// Notify controller of disconnect, allowing it to logout or
		// whatever is appropriate
		binary.Write(conn, binary.BigEndian, byte(2)) // disconnect notification
		binary.Write(conn, binary.BigEndian, uint32(len(vconn.vinztoken)))
		conn.Write([]byte(vconn.vinztoken))
		binary.Write(conn, binary.BigEndian, uint32(len(sessionid)))
		conn.Write([]byte(sessionid))
		binary.Write(conn, binary.BigEndian, byte(255)) // disconnect notification
	}()
	toclient := make(chan []byte)
	go vconn.relayToClient(toclient, wserver)
	if wsclient == nil {
		go vconn.relayPlainToWebsock(vncclient, wserver)
	} else {
		go vconn.relayWebSockToWebsock(wsclient, wserver)
	}
	for {
		msg, more := <- toclient
		if !more {
			break
		}
		if vncclient != nil {
			vncclient.Write(msg)
		} else {
			wsclient.WriteMessage(websocket.BinaryMessage, msg)
		}
	}
	return nil
}

func (vconn *VncConnection) connectToIkvm() (*websocket.Conn, error) {
	target := vconn.hostname
	fprint := vconn.fingperprint
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
	dialer.Subprotocols = vconn.protocols // make([]string, 0)
	// dialer.Subprotocols = append(dialer.Subprotocols, xsrftoken)
	headers := http.Header{}
	headers.Add("Host", hostname)
	targurl := fmt.Sprintf("wss://%s:%d%s", urlhost, vconn.portnum, vconn.targurl)
	SetCookies(targurl, vconn.cookies, dialer.Jar)
	wserver, rsp, err := dialer.Dial(targurl, headers)
	if (rsp.StatusCode == 404) {
		targurl := fmt.Sprintf("wss://%s%s/multi", urlhost, vconn.targurl)
		SetCookies(targurl, vconn.cookies, dialer.Jar)
		wserver, rsp, err = dialer.Dial(targurl, headers)
	}
	if err != nil {
		fmt.Println(err)
		fmt.Println(rsp)
		return nil, err
	}
	return wserver, nil
}
