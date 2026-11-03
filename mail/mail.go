// Package mail sends plain-text email through SES over SMTP, or prints it
// to the log in development.
//
// Every header value is checked for line breaks before the message is
// built, so text a user typed can never add a header or a recipient.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Message is one email.
type Message struct {
	From    mail.Address
	To      []mail.Address
	ReplyTo *mail.Address
	Subject string
	Text    string
}

// Sender sends a message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// ErrHeaderInjection is returned when a header value contains a line break.
var ErrHeaderInjection = errors.New("mail: header value contains a line break")

func clean(s string) error {
	if strings.ContainsAny(s, "\r\n") {
		return ErrHeaderInjection
	}
	return nil
}

func (m Message) validate() error {
	if len(m.To) == 0 {
		return errors.New("mail: no recipient")
	}
	addrs := append([]mail.Address{m.From}, m.To...)
	if m.ReplyTo != nil {
		addrs = append(addrs, *m.ReplyTo)
	}
	for _, a := range addrs {
		if err := clean(a.Name); err != nil {
			return err
		}
		if err := clean(a.Address); err != nil {
			return err
		}
		if _, err := mail.ParseAddress(a.Address); err != nil {
			return fmt.Errorf("mail: bad address %q", a.Address)
		}
	}
	return clean(m.Subject)
}

// Bytes renders the message as RFC 5322 with a fresh Message-ID at the
// sender's domain.
func (m Message) Bytes(now time.Time) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	var to []string
	for _, a := range m.To {
		to = append(to, a.String())
	}
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	domain := m.From.Address[strings.LastIndex(m.From.Address, "@")+1:]
	var b bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", m.From.String())
	h("To", strings.Join(to, ", "))
	if m.ReplyTo != nil {
		h("Reply-To", m.ReplyTo.String())
	}
	h("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	h("Date", now.Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(rnd[:])+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(m.Text, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// SMTP sends through an SMTP server that offers STARTTLS, such as SES on
// port 587. It refuses to send if the server does not offer STARTTLS, so
// credentials never cross the network in the clear.
type SMTP struct {
	Host     string // e.g. email-smtp.ap-southeast-2.amazonaws.com
	Port     int    // 587
	Username string
	Password string
}

func (s SMTP) Send(ctx context.Context, m Message) error {
	msg, err := m.Bytes(time.Now())
	if err != nil {
		return err
	}
	if s.Port == 0 {
		s.Port = 587
	}
	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(60 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return errors.New("mail: server does not offer STARTTLS; refusing to send")
	}
	if err := c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.From.Address); err != nil {
		return err
	}
	for _, a := range m.To {
		if err := c.Rcpt(a.Address); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// Log prints each message instead of sending it. For development only.
type Log struct{ Logger *slog.Logger }

func (l Log) Send(_ context.Context, m Message) error {
	if err := m.validate(); err != nil {
		return err
	}
	var to []string
	for _, a := range m.To {
		to = append(to, a.Address)
	}
	lg := l.Logger
	if lg == nil {
		lg = slog.Default()
	}
	lg.Info("email (not sent)", "to", strings.Join(to, ", "), "subject", m.Subject, "text", m.Text)
	return nil
}
