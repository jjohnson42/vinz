package main

import (
    "fmt"
    "log"
    "github.com/gorilla/websocket"
    "net"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "crypto/tls"
    "strings"
)

type VncConnector struct {
	xsrftoken string
	targurl string
	targbmc string
	jar http.CookieJar

}

func createVncConnector(xsrftoken string, sessionid string, targbmc string) VncConnector {
	var cookies []*http.Cookie
	if strings.Contains(targbmc, ":") {
		targbmc = fmt.Sprintf("[%s]", targbmc)
	}
	jar, _  := cookiejar.New(nil)
	cookie := &http.Cookie{
		Name: "XSRF-TOKEN",
		Value: xsrftoken,
	}
	cookies = append(cookies, cookie)
	cookie = &http.Cookie{
		Name: "SESSION",
		Value: sessionid,
	}
	cookies = append(cookies, cookie)

	targurl := fmt.Sprintf("wss://%s/kvm/0", targbmc)
	targurlparsed, _ := url.Parse(targurl)
	jar.SetCookies(targurlparsed, cookies)
	vc := VncConnector {
		xsrftoken,
		targurl,
		targbmc,
		jar}
	return vc
}

func (vc VncConnector) RelayToWebsock(vncclient net.Conn, wserver *websocket.Conn) {
	inbuffer := make([]byte, 16384)
	mlen, err := vncclient.Read(inbuffer)
	if err != nil {
		fmt.Println(err)
		return
	}
	wserver.WriteMessage(websocket.BinaryMessage, inbuffer[:mlen])
}

func (vc VncConnector) Listen(location string) {
        csock, err := net.Listen("unix", location)
        if err != nil {
                panic(err)
        }
	for {
                conn, err := csock.Accept()
                if err != nil {
                        fmt.Println(err)
                        continue
                }
                go vc.Connect(conn)
	}
}

func (wc VncConnector) RelayToVncClient(vncclient net.Conn, wserver *websocket.Conn) {
	_, msg, err := wserver.ReadMessage()
	if err != nil {
		fmt.Println(err)
		return
	}
	vncclient.Write(msg)
}

func (vc VncConnector) Connect(vncclient net.Conn) {
	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dialer.Jar = vc.jar
	wserver, _, err := dialer.Dial(vc.targurl, nil)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	defer wserver.Close()
	go vc.RelayToWebsock(vncclient, wserver)
	vc.RelayToVncClient(vncclient, wserver)
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
