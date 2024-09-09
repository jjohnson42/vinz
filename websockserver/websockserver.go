package websockserver

import (
	"net"
	"os"
	"fmt"
	"strings"
	"net/http"
	"vinz/vncconnector"
	"github.com/gorilla/websocket"
)

type WebSockServer struct {
	approver string
	authtoken string
}

func (wss *WebSockServer) ServeHTTP(wr http.ResponseWriter, r *http.Request) {
	sessionck, err := r.Cookie("confluentsessionid")
	if err != nil {
		sessionck, err = r.Cookie("SESSIONID")
	}
	if err != nil {
		wr.WriteHeader(401)
		return
	}
	sessionid := sessionck.Value
	subprots := websocket.Subprotocols(r)
	if len(subprots) < 1 {
		wr.WriteHeader(401)
		return
	}
	nodename := strings.Replace(r.URL.Path, "/kvmsession/", "", 1)
	vc, err := vncconnector.CreateVncConnector(wss.approver, "", wss.authtoken, nodename)
	if err != nil {
		wr.WriteHeader(401)
		return
	}
	vconn, err := vc.GetWebsockConnection(sessionid, subprots[0])
	if err != nil {
		wr.WriteHeader(401)
		return
	}
	wsupgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { // stub out origin check
			// We use more strong authentication that origin checking,
			return true
		},
		Subprotocols: subprots,
	}
	conn, err := wsupgrader.Upgrade(wr, r, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	vconn.WebSockConnect((conn))
}
// vconn := vc.GetWebsockConnection(conn, sessionid, subprots[0]}



func CreateWebSockServer(approver string, authtoken string) WebSockServer {
	wss := WebSockServer{approver, authtoken}
	return wss
}

func (wss *WebSockServer) Listen(wpath string) {
	var usock net.Listener
	var err error
	if strings.Contains(wpath, ":") {
		usock, err = net.Listen("tcp", wpath)
	} else {
		usock, err = net.Listen("unix", wpath)
		os.Chmod(wpath, 0o666)
	}
	if err != nil {
		panic(err)
	}
	srv := &http.Server{
		Handler: wss,
	}
	srv.Serve(usock)
}
