package proxy

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

// Convenience variables and utilities.
var urlExample = "https://foo.sso.example.com/path"

func addHeaders(req *http.Request, examples []string, extras map[string][]string) {
	var signedHeaderExamples = map[string][]string{
		"Content-Length":     {"1234"},
		"Content-Md5":        {"F00D"},
		"Content-Type":       {"application/json"},
		"Date":               {"2018-11-08"},
		"Authorization":      {"Bearer ab12cd34"},
		"X-Forwarded-User":   {"octoboi"},
		"X-Forwarded-Email":  {"octoboi@example.com"},
		"X-Forwarded-Groups": {"molluscs", "security_applications"},
	}

	for _, signedHdr := range examples {
		for _, value := range signedHeaderExamples[signedHdr] {
			req.Header.Add(signedHdr, value)
		}
	}
	for extraHdr, values := range extras {
		for _, value := range values {
			req.Header.Add(extraHdr, value)
		}
	}
}

func TestRepr_UrlRepresentation(t *testing.T) {
	testURL := func(url string, expect string) {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Errorf("could not build request: %s", err)
		}

		repr, err := mapRequestToHashInput(req)
		if err != nil {
			t.Errorf("could not map request to hash input: %s", err)
		}
		testutil.Equal(t, expect, repr)
	}

	testURL("http://foo.sso.example.com/path/to/resource", "/path/to/resource")
	testURL("http://foo.sso.example.com/path?", "/path")
	testURL("http://foo.sso.example.com/path/to?query#fragment", "/path/to?query#fragment")
	testURL("https://foo.sso.example.com:4321/path#fragment", "/path#fragment")
	testURL("http://foo.sso.example.com/path?query&param=value#", "/path?query&param=value")
}

func TestRepr_HeaderRepresentation(t *testing.T) {
	testHeaders := func(include []string, extra map[string][]string, expect string) {
		req, err := http.NewRequest("GET", urlExample, nil)
		if err != nil {
			t.Errorf("could not build request: %s", err)
		}
		addHeaders(req, include, extra)
		repr, err := mapRequestToHashInput(req)
		if err != nil {
			t.Errorf("could not map request to hash input: %s", err)
		}
		testutil.Equal(t, expect, repr)
	}

	// Partial set of signed headers.
	testHeaders([]string{"Authorization", "X-Forwarded-Groups"}, nil,
		"Bearer ab12cd34\n"+
			"molluscs,security_applications\n"+
			"/path")

	// Full set of signed headers.
	testHeaders(signedHeaders, nil,
		"1234\n"+
			"F00D\n"+
			"application/json\n"+
			"2018-11-08\n"+
			"Bearer ab12cd34\n"+
			"octoboi\n"+
			"octoboi@example.com\n"+
			"molluscs,security_applications\n"+
			"/path")

	// Partial set of signed headers, plus another header (should not appear in representation).
	testHeaders([]string{"Authorization", "X-Forwarded-Email"},
		map[string][]string{"X-Octopus-Stuff": {"54321"}},
		"Bearer ab12cd34\n"+
			"octoboi@example.com\n"+
			"/path")

	// Only unsigned headers.
	testHeaders(nil, map[string][]string{"X-Octopus-Stuff": {"83721"}}, "/path")
}

func TestRepr_PostWithBody(t *testing.T) {
	req, err := http.NewRequest("POST", urlExample, strings.NewReader("something\nor other"))
	if err != nil {
		t.Errorf("could not build request: %s", err)
	}
	addHeaders(req, []string{"X-Forwarded-Email", "X-Forwarded-Groups"},
		map[string][]string{"X-Octopus-Stuff": {"54321"}})

	repr, err := mapRequestToHashInput(req)
	if err != nil {
		t.Errorf("could not map request to hash input: %s", err)
	}
	testutil.Equal(t,
		"octoboi@example.com\n"+
			"molluscs,security_applications\n"+
			"/path\n"+
			"something\n"+
			"or other",
		repr)
}

func TestSignatureRoundTripDecoding(t *testing.T) {
	// Keys used for signing/validating request. Generated only for testing this package.
	privateKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCy38IQCH8QyeNF
s1zA0XuIyqnTcSfYZg0nPfB+K//pFy7tIOAwmR6th8NykrxFhEQDHKNCmLXt4j8V
FDHQZtGjUBHRmAXZW8NOQ0EI1vc/Dpt09sU40JQlXZZeL+9/7iAxEfSE3TQr1k7P
Xwxpjm9rsLSn7FoLnvXco0mc6+d2jjxf4cMgJIaQLKOd783KUQzLVEvBQJ05JnpI
2xMjS0q33ltMTMGF3QZQN9i4bZKgnItomKxTJbfxftO11FTNLB7og94sWmlThAY5
/UMjZaWYJ1g89+WUJ+KpVYyJsHPBBkaQG+NYazcLDyIowpzJ1WVkInysshpTqwT+
UPV4at+jAgMBAAECggEAX8lxK5LRMJVcLlwRZHQJekRE0yS6WKi1jHkfywEW5qRy
jatYQs4MXpLgN/+Z8IQWw6/XQXdznTLV4xzQXDBjPNhI4ntNTotUOBnNvsUW296f
ou/uxzDy1FuchU2YLGLBPGXIEko+gOcfhu74P6J1yi5zX6UyxxxVvtR2PCEb7yDw
m2881chwMblZ5Z8uyF++ajkK3/rqLk64w29+K4ZTDbTcCp5NtBYx2qSEU7yp12rc
qscUGqxG00Abx+osI3cUn0kOq7356LeR1rfA15yZwOb+s28QYp2WPlVB2hOiYXQv
+ttEOpt0x1QJhBAsFgwY173sD5w2MryRQb1RCwBvqQKBgQDeTdbRzxzAl83h/mAq
5I+pNEz57veAFVO+iby7TbZ/0w6q+QeT+bHF+TjGHiSlbtg3nd9NPrex2UjiN7ej
+DrxhsSLsP1ZfwDNv6f1Ii1HluJclUFSUNU/LntBjqqCJ959lniNp1y5+ZQ/j2Rf
+ZraVsHRB0itilFeAl5+n7CfxwKBgQDN/K+E1TCbp1inU60Lc9zeb8fqTEP6Mp36
qQ0Dp+KMLPJ0xQSXFq9ILr4hTJlBqfmTkfmQUcQuwercZ3LNQPbsuIg96bPW73R1
toXjokd6jUn5sJXCOE0RDumcJrL1VRf9RN1AmM4CgCc/adUMjws3pBc5R4An7UyU
ouRQhN+5RQKBgFOVTrzqM3RSX22mWAAomb9T09FxQQueeTM91IFUMdcTwwMTyP6h
Nm8qSmdrM/ojmBYpPKlteGHdQaMUse5rybXAJywiqs84ilPRyNPJOt8c4xVOZRYP
IG62Ck/W1VNErEnqBn+0OpAOP+g6ANJ5JfkL/6mZJIFjbT58g4z2e9FHAoGBAM3f
uBkd7lgTuLJ8Gh6xLVYQCJHuqZ49ytFE9qHpwK5zGdyFMSJE5OlS9mpXoXEUjkHk
iraoUlidLbwdlIr6XBCaGmku07SFXTNtOoIZpjEhV4c762HTXYsoCWos733uD2zt
z+iJEJVFOnTRtMK5kO+KjD+Oa9L8BCcmauTi+Ku1AoGAZBUzi95THA60hPXI0hm/
o0J5mfLkFPfhpUmDAMaEpv3bM4byA+IGXSZVc1IZO6cGoaeUHD2Yl1m9a5tv5rF+
FS9Ht+IgATvGojah+xxQy+kf6tRB9Hn4scyq+64AesXlDbWDEagomQ0hyV/JKSS6
LQatvnCmBd9omRT2uwYUo+o=
-----END PRIVATE KEY-----`
	publicKey := `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAst/CEAh/EMnjRbNcwNF7iMqp03En2GYNJz3wfiv/6Rcu7SDgMJke
rYfDcpK8RYREAxyjQpi17eI/FRQx0GbRo1AR0ZgF2VvDTkNBCNb3Pw6bdPbFONCU
JV2WXi/vf+4gMRH0hN00K9ZOz18MaY5va7C0p+xaC5713KNJnOvndo48X+HDICSG
kCyjne/NylEMy1RLwUCdOSZ6SNsTI0tKt95bTEzBhd0GUDfYuG2SoJyLaJisUyW3
8X7TtdRUzSwe6IPeLFppU4QGOf1DI2WlmCdYPPfllCfiqVWMibBzwQZGkBvjWGs3
Cw8iKMKcydVlZCJ8rLIaU6sE/lD1eGrfowIDAQAB
-----END RSA PUBLIC KEY-----`

	// Build the RequestSigner object used to generate the request signature header.
	requestSigner, err := NewRequestSigner(privateKey)
	testutil.Assert(t, err == nil, "could not initialize request signer: %s", err)

	// And build the rsa.PublicKey object that will help verify the signature.
	verifierKey, err := func() (*rsa.PublicKey, error) {
		if block, _ := pem.Decode([]byte(publicKey)); block == nil {
			return nil, fmt.Errorf("could not read PEM block from public key")
		} else if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("could not read key from public key bytes: %s", err)
		} else {
			return key, nil
		}
	}()
	testutil.Assert(t, err == nil, "could not construct public key: %s", err)

	// Build the Request to be signed.
	req, err := http.NewRequest("POST", urlExample, strings.NewReader("something\nor other"))
	testutil.Assert(t, err == nil, "could not construct request: %s", err)
	addHeaders(req, []string{"X-Forwarded-Email", "X-Forwarded-Groups"},
		map[string][]string{"X-Octopus-Stuff": {"54321"}})

	// Sign the request, and extract its signature from the header.
	requestSigner.Sign(req)
	sig, _ := base64.URLEncoding.DecodeString(req.Header["Octoboi-Signature"][0])

	// Hardcoded expected hash, computed from the request.
	expectedHash, _ := hex.DecodeString(
		"04158c00fbecccd8b5dca58634a0a7f28bf5ad908f19cb1b404bdd37bb4485a9")
	err = rsa.VerifyPKCS1v15(verifierKey, crypto.SHA256, expectedHash, sig)
	testutil.Assert(t, err == nil, "could not verify request signature: %s", err)
}
