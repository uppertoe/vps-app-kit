package mail

import (
	"errors"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestHeaderInjectionRefused(t *testing.T) {
	base := Message{
		From:    mail.Address{Name: "Dept", Address: "dept@example.org"},
		To:      []mail.Address{{Address: "ann@example.org"}},
		Subject: "Hello",
		Text:    "Body\nline two",
	}
	if _, err := base.Bytes(time.Now()); err != nil {
		t.Fatal(err)
	}
	bad := []Message{base, base, base}
	bad[0].Subject = "Hi\r\nBcc: victim@example.org"
	bad[1].To = []mail.Address{{Name: "Ann\nBcc: x@y.z", Address: "ann@example.org"}}
	bad[2].ReplyTo = &mail.Address{Address: "a@b.c\r\nX: y"}
	for i, m := range bad {
		if _, err := m.Bytes(time.Now()); !errors.Is(err, ErrHeaderInjection) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

func TestRendering(t *testing.T) {
	m := Message{
		From:    mail.Address{Name: "Département", Address: "dept@example.org"},
		To:      []mail.Address{{Address: "ann@example.org"}},
		Subject: "Rendez-vous à l'hôpital",
		Text:    "Line one\nLine two",
	}
	b, err := m.Bytes(time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"Subject: =?utf-8?q?", "Message-ID: <", "@example.org>", "Line one\r\nLine two"} {
		if !strings.Contains(s, want) {
			t.Errorf("message lacks %q:\n%s", want, s)
		}
	}
}

func TestLineEndings(t *testing.T) {
	m := Message{From: mail.Address{Address: "d@example.org"}, To: []mail.Address{{Address: "a@example.org"}}, Subject: "s",
		Text: "one\r\ntwo\nthree\rfour"}
	b, err := m.Bytes(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body := string(b[strings.Index(string(b), "\r\n\r\n")+4:])
	if body != "one\r\ntwo\r\nthree\r\nfour" {
		t.Fatalf("body %q", body)
	}
	if strings.Contains(string(b), "\r\r") {
		t.Fatal("CR CR in the message")
	}
}
