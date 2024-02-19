//go:build !aws
// +build !aws

package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/go-errors/errors"
)

// SendEmail sends an email using SES infrastructure
func SendEmail(from string, to string, subject string, body string) error {
	return SendEmails(from, []string{to}, []string{}, subject, body)
}

// SendEmails sends multiple emails using SES infrastructure
func SendEmails(from string, to []string, cc []string, subject string, body string) error {
	e := NewEmail(from, to, subject)
	e.Cc = cc
	e.Body = body
	err := e.Send()
	return err
}

type MultipartAttach struct {
	Name        string
	ContentType string
	Data        []byte
}

type Email struct {
	From        string
	To          []string
	Cc          []string
	ReplyTo     []string // not implemented in multipart
	Subject     string
	Body        string
	ContentType string
	Attachments []MultipartAttach
}

func NewEmail(from string, to []string, subject string) Email {
	return Email{
		From:        from,
		To:          to,
		Cc:          []string{},
		ReplyTo:     []string{},
		Subject:     subject,
		Attachments: []MultipartAttach{},
	}
}

// ContentType is only used for multipart emails. For simple emails, body must be HTML
func (e *Email) SetBody(body string, contentType string) {
	e.Body = body
	e.ContentType = contentType
}

// This only works for multipart emails
func (e *Email) AddAttachment(name string, data []byte, contentType string) {
	e.Attachments = append(e.Attachments, MultipartAttach{
		Name:        name,
		Data:        data,
		ContentType: contentType,
	})
}

func (e Email) Send() error {
	var charset = "UTF-8"
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-west-1"))
	if err == nil {
		client := ses.NewFromConfig(cfg)

		_, err = client.SendEmail(context.TODO(), &ses.SendEmailInput{
			Destination: &types.Destination{
				ToAddresses: e.To,
				CcAddresses: e.Cc,
			},
			ReplyToAddresses: e.ReplyTo,
			Message: &types.Message{
				Body: &types.Body{
					Html: &types.Content{
						Charset: &charset,
						Data:    &e.Body,
					},
				},
				Subject: &types.Content{
					Charset: &charset,
					Data:    &e.Subject,
				},
			},
			Source: &e.From,
		})

	}
	return err
}

func (e Email) SendMultipart() error {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-west-1"))
	if err == nil {
		client := ses.NewFromConfig(cfg)
		// https://zetcode.com/golang/email-smtp/?utm_content=cmp-true
		var buf bytes.Buffer
		buf.WriteString(fmt.Sprintf("From: %s\r\n", e.From))
		buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(e.To, ";")))
		if len(e.Cc) > 0 {
			buf.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(e.Cc, ";")))
		}
		buf.WriteString(fmt.Sprintf("Subject: %s\r\n", e.Subject))
		boundary := "gockham-boundary-42"
		buf.WriteString("MIME-Version: 1.0\r\n")
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\n", boundary))

		buf.WriteString(fmt.Sprintf("\r\n--%s\r\n", boundary))
		buf.WriteString("Content-Type:" + e.ContentType + "\r\n")
		buf.WriteString(fmt.Sprintf("\r\n%s", e.Body))

		for _, att := range e.Attachments {
			buf.WriteString(fmt.Sprintf("\r\n--%s\r\n", boundary))

			buf.WriteString("Content-Type: " + att.ContentType + "\r\n")
			buf.WriteString("Content-Transfer-Encoding: base64\r\n")
			buf.WriteString("Content-Disposition: attachment; filename=" + att.Name + "\r\n")
			buf.WriteString("Content-ID: <" + att.Name + ">\r\n\r\n")

			b := make([]byte, base64.StdEncoding.EncodedLen(len(att.Data)))
			base64.StdEncoding.Encode(b, att.Data)
			buf.Write(b)
			buf.WriteString(fmt.Sprintf("\r\n--%s\n\r", boundary))
		}
		buf.WriteString("--")
		_, err = client.SendRawEmail(context.TODO(), &ses.SendRawEmailInput{
			// Source:       &from,
			// Destinations: dest,
			RawMessage: &types.RawMessage{
				Data: buf.Bytes(),
			},
		})
	}
	return err
}

// TemplateRenderer renders templates using Go template engine
type TemplateRenderer struct {
	ctx   Context            // Map with values used for rendering the template
	lang  string             // Language to use for I18N texts
	tplts *template.Template // The template
	i18n  *JSONResource      // I18N texts
}

// NewTemplateRenderer creates a new template renderer
func NewTemplateRenderer(lang string, i18n *JSONResource) *TemplateRenderer {
	return &TemplateRenderer{
		lang: lang,
		i18n: i18n,
	}
}

// Parse parses a template. delims are the optional tag delimiters (by default {{ and }})
func (t *TemplateRenderer) Parse(url string, delims ...string) error {
	url = strings.Replace(url, "[lang]", t.lang, 1)
	if t.tplts == nil {
		t.tplts = template.New(path.Base(url)).Funcs(template.FuncMap{"I18N": func(key string) string { return t.i18n.Text(key, t.lang) }})
	}
	if len(delims) > 0 {
		t.tplts = t.tplts.Delims(delims[0], delims[1])
	}

	tplt, err := ReadUrl(url)
	if err == nil {
		t.tplts, err = t.tplts.Parse(string(tplt))
	}
	return err
}

// Render renders a template with given context
func (t *TemplateRenderer) Render(ctx Context) (string, error) {
	t.ctx = ctx
	buf := new(bytes.Buffer)
	err := t.tplts.Execute(buf, ctx)
	return buf.String(), err
}

