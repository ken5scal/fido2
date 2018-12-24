package main

import (
	"encoding/base64"
	"fmt"
	"unicode/utf8"
	"crypto/sha256"
	"github.com/ugorji/go/codec"
	"encoding/json"
	"github.com/pkg/errors"
	"bytes"
)

//============================================
// Attestation Object
//============================================

// Attestation Object
// https://www.w3.org/TR/webauthn/#generating-an-attestation-object
type AttestationObject struct {
	Fmt string `codec:"fmt"`
	//AttStmt []byte  `codec:"attStmt"`
	AttStmt  AttestationStmt `codec:"attStmt"`
	AuthData []byte          `codec:"authData"`
}

// AttestationStatement
// The format varies based on Attestation Format
// https://www.w3.org/TR/webauthn/#sctn-attstn-fmt-ids

type AttestationStmt interface {
	Verify() bool
}

// AndroidSafetyNetAttestationStmt
// https://www.w3.org/TR/webauthn/#android-safetynet-attestation
type AndroidSafetyNetAttestationStmt struct {
	Ver      string `codec:"ver"`      // The version number of Google Play Services responsible for providing the SafetyNet API
	Response []byte `codec:"response"` //The UTF-8 encoded result of the getJwsResult() call of the SafetyNet API. This value is a JWS object
}

func (a AndroidSafetyNetAttestationStmt) Verify() bool {
	return false
}

type AndroidSafetyNetAttestationResponse struct {
	Nonce                      string   `json:"nonce"`
	TimestampMs                int64    `json:"timestampMs"`
	ApkPackageName             string   `json:"apkPackageName"`
	ApkCertificateDigestSha256 []string `json:"apkCertificateDigestSha256"`
	ApkDigestSha256            string `json:"apkDigestSha256"`
	CtsProfileMatch            bool   `json:"ctsProfileMatch"`
	BasicIntegrity            bool   `json:"basicIntegrity"`
}

// ValidateClientData follows requirements from https://www.w3.org/TR/webauthn/#registering-a-new-credential
// x.x.x represents each criteria
// TODO challenge needs to be extracted from DB or some kind of data storage
func (s ServerAuthenticatorAttestationResponse) ValidateClientData(challenge, origin string) ([]byte, error) {
	clientDataInBytes, err := base64.RawURLEncoding.DecodeString(s.ClientDataJSON)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decode ClientDataJSON in Base64 URL format: %v", s.ClientDataJSON))
	}

	// 7.1.1
	if !utf8.Valid(clientDataInBytes) {
		return nil, errors.New(fmt.Sprintf("Invalid UTF8 encoded value: %v", clientDataInBytes))
	}

	// 7.1.2
	var clientData ClientData
	if err := json.Unmarshal(clientDataInBytes, &clientData); err != nil {
		return nil, errors.New("Failed Unmarshal ClientDataJSON")
	}

	// 7.1.3
	// TODO make this enum and check the value
	if clientData.Type != "webauthn.create" {
		return nil, errors.New("ClientData type is not 'webauthn.create'")
	}

	// 7.1.4
	if clientData.Challenge != challenge {
		errorMessage := "Challenge from Client Data is not same as the one from ServerPublicKeyCredentialCreationOptionsResponse\n"
		errorMessage += fmt.Sprintf("Expected %s, but was %s", challenge, clientData.Challenge)
		return nil, errors.New(errorMessage)
	}

	// 7.1.5
	if clientData.Origin != origin {
		errorMessage := "ClientData challenge is not same as the origin\n"
		errorMessage += fmt.Sprintf("Expected %s, but was %s", origin, clientData.Origin)
		return nil, errors.New(errorMessage)
	}

	// 7.1.6
	// TODO Skip for now (Got No Idea)
	//if clientData.TokenBiding.TokenBindingStatus == {
	//
	//}

	// 7.1.7
	sha := sha256.New()
	sha.Write(clientDataInBytes)
	hashOfClientData := sha.Sum(nil) // This value is used id 7.1.14

	return hashOfClientData, nil
}

// ValidateAuthData follows requirements from https://www.w3.org/TR/webauthn/#registering-a-new-credential
// x.x.x represents each criteria
func (s ServerAuthenticatorAttestationResponse) ValidateAuthData(rpId string, requiresUserVerification bool) ([]byte, error) {
	// 7.1.8
	cborByte := make([]byte, base64.RawURLEncoding.DecodedLen(len(s.AttestationObject)))
	cborByte, err := base64.RawURLEncoding.DecodeString(s.AttestationObject)
	if err != nil {
		return nil, errors.Wrap(err, "failed base64 url decoding AttestationObject")
	}

	ao := AttestationObject{}
	// TODO Need to find a way to do like jws in go-jose.v2 because ao.attStmt would vary based on ao.fmt
	// Make a fake "original" rawSignatureInfo to store the unprocessed
	// Protected header. This is necessary because the Protected header can
	// contain arbitrary fields not registered as part of the spec. See
	// https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
	// If we unmarshal Protected into a rawHeader with its explicit list of fields,
	// we cannot marshal losslessly. So we have to keep around the original bytes.
	// This is used in computeAuthData, which will first attempt to use
	// the original bytes of a protected header, and fall back on marshaling the
	// header struct only if those bytes are not available.
	ao.AttStmt = &AndroidSafetyNetAttestationStmt{}
	if err := codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&ao); err != nil {
		return nil, errors.Wrap(err, "failed cbor decoding AttestationObject")
	}

	// 7.1.9 Verifying that the RP ID hash in auth Data is sha256 of RP ID
	// AuthData: https://www.w3.org/TR/webauthn/#authenticator-data
	if len(ao.AuthData) < 37 {
		return nil, errors.New("AuthData must be 37 bytes or more")
	}
	sha := sha256.New()
	sha.Write([]byte(rpId))
	rpIdHash := sha.Sum(nil)

	if bytes.Compare(rpIdHash, ao.AuthData[0:32]) != 0 {
		errorMessage := "RP ID Hash in authData is not SHA-256 hash of the RP ID\n"
		errorMessage += fmt.Sprintf("Expected %x, but was %x", rpIdHash, ao.AuthData[0:32])
		return nil, errors.New(errorMessage)
	}

	// 7.1.10
	flags := ao.AuthData[32]
	up := flags & (1 << 0) >> 0
	if up == 0 {
		// https://www.w3.org/TR/webauthn/#test-of-user-presence
		return nil, errors.New("Requires user interaction with an authenticator (Not necessary has to be verification)")
	}

	// 7.1.11
	uv := flags & (1 << 2) >> 2
	if requiresUserVerification && uv == 0 {
		return nil, errors.New("Requires user verification by an authenticator.")
	}

	//attestedClientData := flags & (1 << 6) >> 6
	// 7.1.12 Verifying the client extension
	// TODO Study and implement extetion verification
	doesIncludeExtensions := flags & (1 << 7) >> 7 // https://www.w3.org/TR/webauthn/#sctn-extension-id
	if doesIncludeExtensions == 1 {}

	// 7.1.13 Determine the attestation statement
	// 7.1.14 Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.
	// 7.1.15 If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy.
	// 7.1.16 Assess the attestation trustworthiness using the outputs of the verification procedure in step 14
	// TODO 7.1.19 If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.
	switch ao.Fmt {
	case "packed":
	case "tpm":
	case "android-key":
	case "android-safetynet":
	case "fido-u2f":
	case "none":
	}

	return nil, nil
}