//go:build !aws
// +build !aws

package tools

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/golang-jwt/jwt/v5"
)

var Debug = os.Getenv("DEBUG") == "true"

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
			// buf.Write(b)
			// Write in chunks of 80 characters
			for i := 0; i < len(b); i += 80 {
				end := i + 80
				if end > len(b) {
					end = len(b)
				}
				buf.WriteString(string(b[i:end]) + "\n")
			}
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

// ReadURL reads a URL and returns its contents. If the URL starts with "file://"
// then a file is read, otherwise HTTP its used
func ReadUrl(url string) (string, error) {
	if strings.HasPrefix(url, "file://") {
		file := url[7:]
		b, err := os.ReadFile(file)
		return string(b), err
	}

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(url + " responded with status code " + strconv.Itoa(resp.StatusCode))
	}
	defer resp.Body.Close()
	body, err2 := io.ReadAll(resp.Body)
	return string(body), err2
}

// PostURL posts a JSON in the request body and returns the response
func PostUrlJson(url string, params map[string]any) (string, error) {
	jsonValue, _ := json.Marshal(params)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(url + " responded with status code " + strconv.Itoa(resp.StatusCode))
	}
	defer resp.Body.Close()
	body, err2 := io.ReadAll(resp.Body)
	return string(body), err2
}

// Context is just another way of calling a map of strings keys and any values.
type Context = map[string]any

func NewContext(m map[string]string) Context {
	ctx := Context{}
	for key, value := range m {
		ctx[key] = value
	}
	return ctx
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
	tplt, err := ReadUrl(url)
	if err == nil {
		err = t.ParseString(path.Base(url), string(tplt), delims...)
	}
	return err
}

func (t *TemplateRenderer) ParseEmbedded(fs embed.FS, file string, delims ...string) error {
	file = strings.Replace(file, "[lang]", t.lang, 1)
	tplt, err := fs.ReadFile(file)
	if err == nil {
		err = t.ParseString(path.Base(file), string(tplt), delims...)
	}
	return err
}

func (t *TemplateRenderer) ParseString(name string, tplt string, delims ...string) (err error) {
	if t.tplts == nil {
		t.tplts = template.New(name).Funcs(template.FuncMap{"I18N": func(key string) string { return t.i18n.Text(key, t.lang) }})
	}
	if len(delims) > 0 {
		t.tplts = t.tplts.Delims(delims[0], delims[1])
	}
	t.tplts, err = t.tplts.Parse(string(tplt))
	return err
}

// Render renders a template with given context
func (t *TemplateRenderer) Render(ctx Context) (string, error) {
	t.ctx = ctx
	buf := new(bytes.Buffer)
	err := t.tplts.Execute(buf, ctx)
	return buf.String(), err
}

// GetURLSignature generates a JWT token that is valid for accessing to a
// signed URL for ttl seconds. Extra claims can be provided in the signature.
// The signature should be included in the URL as the query string parameter 'signature'.
func GetURLSignature(url string, key []byte, ttl int, claims jwt.MapClaims) (string, error) {
	if ttl > 0 {
		t := time.Now().Unix()
		claims["exp"] = t + int64(ttl)
		claims["url"] = url
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

// ParseToken parses a JWT token and validates its signature
func ParseToken(token string, key []byte) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
}

// JSONResource represents a URL resource that contains JSON
type JSONResource struct {
	URL  string                 // URL where to get data from
	Fs   *embed.FS              // Embedded file system
	json map[string]interface{} // The actual unmarshalled data
}

// Get reads the URL and unmarshalls the JSON data
func (j *JSONResource) Get() (map[string]interface{}, error) {
	if j.json == nil {
		var str string
		var err error
		if j.Fs == nil {
			str, err = ReadUrl(j.URL)
		} else {
			var bytes []byte
			bytes, err = j.Fs.ReadFile(j.URL)
			str = string(bytes)
		}
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal([]byte(str), &j.json)
		if err != nil {
			return nil, err
		}
	}
	return j.json, nil
}

// Text takes a key and an idiom and gets the corresponding I18N text
// This shouls not be in JsonResource but in I18NResource
func (j *JSONResource) Text(key string, lang string) string {
	parts := strings.Split(key, ".")
	current, err := j.Get()
	if err != nil {
		return err.Error()
	}
	for _, v := range parts {
		current = current[v].(map[string]interface{})
	}
	return current[lang].(string)
}

// CreateTempFile creates a temporary file
func CreateTempFile(tmpDir string, name string, content string) (*os.File, error) {
	file, err := os.CreateTemp(tmpDir, name)
	if err == nil {
		_, err = file.Write([]byte(content))
		return file, err
	}
	return nil, err
}

// RenderFOP renders a document from a XSL and XML executing FOP on a shell. xml is
// the actual XML content while xslPath and configPath are the path to the xsl and config
// file respectively.
// format can be any fop supported format, like "pdf" or "rtf"
func RenderFOP(xml string, xslPath string, configPath string, format string) ([]byte, error) {
	os.MkdirAll("tmp", 0700)
	// save files to disk
	xmlFile, err := CreateTempFile("tmp", "xml", xml)
	if err == nil {
		defer func() {
			os.Remove(xmlFile.Name())
		}()

		// Execute FOP
		cmd := exec.Command("/usr/bin/fop", "-xsl", xslPath, "-xml", xmlFile.Name(), "-c", configPath, "-"+format, "-")
		// cmd.Dir = "/home/kurt/IdeaProjects/nadir/xsl/test"
		var stdout, stderr io.ReadCloser
		stdout, err = cmd.StdoutPipe()
		stderr, _ = cmd.StderrPipe()
		if err == nil {
			err = cmd.Start()
			if err == nil {
				pdf := new(bytes.Buffer)
				io.Copy(pdf, stdout)
				errout := new(bytes.Buffer)
				io.Copy(errout, stderr)
				err = cmd.Wait()
				stdout.Close()
				stderr.Close()
				if Debug {
					fmt.Println("RenderPDF stderr:", errout)
				}
				if err != nil {
					return nil, errors.New(errout.String())
				}
				return pdf.Bytes(), nil
			}
		}
	}
	return nil, err
}
