package bad

import (
	"html/template"
	"net"
	h "net/http"
	"os/exec"
)

func f() {
	h.Get("https://x.org")
	_ = h.DefaultClient
	_ = &h.Client{}
	_ = h.Transport{}
	net.Dial("tcp", "x:1")
	_ = &net.Dialer{}
	exec.Command("sh")
	_ = template.HTML("<b>x</b>")
}
