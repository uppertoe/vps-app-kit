package bad

import (
	"net/http"
	"net/http/httputil"
	"net/smtp"
	"os"
	"syscall"
)

type holder struct {
	c http.Client
}

var direct http.Client

func evade() {
	_ = new(http.Client)
	_ = httputil.NewSingleHostReverseProxy(nil)
	_, _ = os.StartProcess("/bin/sh", nil, nil)
	_ = syscall.Exec("/bin/sh", nil, nil)
	_ = smtp.SendMail("x:25", nil, "", nil, nil)
	var t *http.Transport
	_ = t
}
