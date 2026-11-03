package bad

import (
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
}
