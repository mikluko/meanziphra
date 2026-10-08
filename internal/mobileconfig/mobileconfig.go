// Package mobileconfig собирает профиль конфигурации iOS, который ставит якорь доверенным корнем,
// а кросс-сертификаты — промежуточными.
package mobileconfig

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"howett.net/plist"
)

// Identifier — PayloadIdentifier профиля. Профиль с тем же идентификатором iOS ставит вместо прежнего.
const Identifier = "io.github.mikluko.meanziphra"

type payload struct {
	PayloadType                string `plist:"PayloadType"`
	PayloadVersion             int    `plist:"PayloadVersion"`
	PayloadIdentifier          string `plist:"PayloadIdentifier"`
	PayloadUUID                string `plist:"PayloadUUID"`
	PayloadDisplayName         string `plist:"PayloadDisplayName"`
	PayloadCertificateFileName string `plist:"PayloadCertificateFileName"`
	PayloadContent             []byte `plist:"PayloadContent"`
}

type profile struct {
	PayloadType        string    `plist:"PayloadType"`
	PayloadVersion     int       `plist:"PayloadVersion"`
	PayloadIdentifier  string    `plist:"PayloadIdentifier"`
	PayloadUUID        string    `plist:"PayloadUUID"`
	PayloadDisplayName string    `plist:"PayloadDisplayName"`
	PayloadDescription string    `plist:"PayloadDescription"`
	PayloadContent     []payload `plist:"PayloadContent"`
}

// Build возвращает XML-plist профиля с именем name: anchor как com.apple.security.root и каждый из crosses
// как com.apple.security.pkcs1.
func Build(name, description string, anchor *x509.Certificate, crosses []*x509.Certificate) ([]byte, error) {
	p := profile{
		PayloadType:        "Configuration",
		PayloadVersion:     1,
		PayloadIdentifier:  Identifier,
		PayloadDisplayName: name,
		PayloadDescription: description,
	}
	var err error
	if p.PayloadUUID, err = uuid(); err != nil {
		return nil, err
	}
	certs := append([]*x509.Certificate{anchor}, crosses...)
	for i, c := range certs {
		pl := payload{
			PayloadType:                "com.apple.security.pkcs1",
			PayloadVersion:             1,
			PayloadIdentifier:          fmt.Sprintf("%s.cross%d", Identifier, i),
			PayloadDisplayName:         c.Subject.CommonName,
			PayloadCertificateFileName: fmt.Sprintf("cross%d.cer", i),
			PayloadContent:             c.Raw,
		}
		if i == 0 {
			pl.PayloadType = "com.apple.security.root"
			pl.PayloadIdentifier = Identifier + ".anchor"
			pl.PayloadCertificateFileName = "anchor.cer"
		}
		if pl.PayloadUUID, err = uuid(); err != nil {
			return nil, err
		}
		p.PayloadContent = append(p.PayloadContent, pl)
	}
	return plist.MarshalIndent(p, plist.XMLFormat, "\t")
}

// uuid возвращает случайный UUID версии 4 в верхнем регистре, как его пишут профили Apple.
func uuid() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
