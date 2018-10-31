package proxy

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"strings"
)

// Constants.
var signedHeaders = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Groups",
	"Cookie",
}
var signatureHeader = "Octoboi-Signature"

// RequestSigner type.
type RequestSigner struct {
	hasher       hash.Hash
	signingKey   crypto.Signer
	publicKeyStr string
}

// NewRequestSigner constructs an object capable of signing requests with a public key.
func NewRequestSigner(signingKeyPemStr string) (*RequestSigner, error) {
	var privateKey crypto.Signer
	var publicKey string

	// Build private key.
	if block, _ := pem.Decode([]byte(signingKeyPemStr)); block == nil {
		return nil, fmt.Errorf("could not read PEM block from signing key")
	} else if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("could not read key from signing key bytes: %s", err)
	} else {
		privateKey = key.(crypto.Signer)
	}

	// Derive public key.
	rsaPublicKey, ok := privateKey.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only RSA public keys are currently supported")
	}
	publicKey = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(rsaPublicKey),
		}))

	return &RequestSigner{
		hasher:       sha256.New(),
		signingKey:   privateKey,
		publicKeyStr: publicKey,
	}, nil
}

// mapRequestToHashInput returns a string representation of a Request, formatted as a
// newline-separated sequence of entries from the request. Any two Requests sharing the same
// representation are considered "equal" for purposes of verifying the integrity of a request.
//
// Representations are formatted as follows:
//   <HEADER.1>
//   ...
//   <HEADER.N>
//   <URL>
//   <BODY>
//  where:
//    <HEADER.k> is the ','-joined concatenation of values set for the k'th header from
//      `signedHeaders`; all other headers in the request are ignored,
//    <URL> is the string "<PATH>(?<QUERY>)(#FRAGMENT)", where "?<QUERY>" and "#<FRAGMENT>" are
//      ommitted if the associated components are absent from the request URL,
//    <BODY> is the body of the Request (may be nil for GET requests).
//
//  Receiving endpoints authenticating the integrity of a request should reconstruct this document
//  exactly, when verifying the contents of a received request.
func mapRequestToHashInput(req *http.Request) (string, error) {
	entries := []string{}

	// Add signed headers.
	for _, hdr := range signedHeaders {
		if hdrValues := req.Header[hdr]; len(hdrValues) > 0 {
			entries = append(entries, strings.Join(hdrValues, ","))
		}
	}

	// Add canonical URL representation. Ignore URL {scheme, host, port, etc}.
	entries = append(entries, func() string {
		url := req.URL.Path
		if len(req.URL.RawQuery) > 0 {
			url += ("?" + req.URL.RawQuery)
		}
		if len(req.URL.Fragment) > 0 {
			url += ("#" + req.URL.Fragment)
		}
		return url
	}())

	// Add request body, if present (may be absent for GET requests, etc).
	if req.Body != nil {
		body, _ := ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		entries = append(entries, string(body))
	}

	// Return the join of all entries, with each separated by a newline.
	return strings.Join(entries, "\n"), nil
}

// Sign adds a header to the request, with a public-key encrypted signature of a subset of the
// request headers, together with the request body.
//
// Signature is computed as:
//   repr := Representation(request)  <- Computed by mapRequestToHashInput()
//   hash := SHA256(repr)
//   sig  := SIGN(hash, SigningKey)
//   final := WEB_SAFE_BASE64(sig)
// The header defined in `signatureHeader` (see above) is given the value of `final`.
//
// Receiving endpoints authenticating the integrity of a request should:
//   1. Strip the WEB_SAFE_BASE64 encoding from the value of `signatureHeader`,
//   2. Decrypt the resulting value using the public key published by sso_proxy to obtain the hash
//      of the request representation,
//   3. Compute the request representation from the received request, using the same format as the
//      mapRequestToHashInput() function above,
//   4. Apply SHA256 hash to the recomputed representation, and verify that it matches the decrypted
//      hash value received through the `signatureHeader` of the request.
//
//  Any requests failing this check should be considered tampered with, and rejected.
func (signer RequestSigner) Sign(req *http.Request) error {
	// Hash options (satisfies crypto.SignerOpts interface).

	// Generate the request representation that will serve as hash input.
	repr, err := mapRequestToHashInput(req)
	if err != nil {
		return fmt.Errorf("could not generate representation for request: %s", err)
	}

	// Generate hash of the document buffer.
	var documentHash []byte
	signer.hasher.Reset()
	_, _ = signer.hasher.Write([]byte(repr))
	documentHash = signer.hasher.Sum(documentHash)

	// Sign the documentHash with the signing key.
	signatureBytes, err := signer.signingKey.Sign(rand.Reader, documentHash, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed signing document hash with signing key: %s", err)
	}
	signature := base64.URLEncoding.EncodeToString(signatureBytes)

	// Set the signature-header on the rest. Return `nil` to indicate no error.
	req.Header.Set(signatureHeader, signature)
	return nil
}

// PublicKey returns a string PEM-encoded representation of the public key associated with the
// private key used to sign requests.
func (signer RequestSigner) PublicKey() string {
	return signer.publicKeyStr
}
