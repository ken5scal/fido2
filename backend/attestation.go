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
	"gopkg.in/square/go-jose.v2/jwt"
	"crypto/x509"
)

//============================================
// Attestation Object
//============================================

// Attestation Object
// https://www.w3.org/TR/webauthn/#generating-an-attestation-object
type AttestationObject struct {
	Fmt string `codec:"fmt"`
	AttStmt  AttestationStmt `codec:"attStmt"`
	AuthData []byte          `codec:"authData"`
}

// AttestationStatement
// The format varies based on Attestation Format
// https://www.w3.org/TR/webauthn/#sctn-attstn-fmt-ids

type AttestationStmt interface {
	Verify() error
}

// AndroidSafetyNetAttestationStmt
// https://www.w3.org/TR/webauthn/#android-safetynet-attestation
type AndroidSafetyNetAttestationStmt struct {
	Ver      string `codec:"ver"`      // The version number of Google Play Services responsible for providing the SafetyNet API
	Response []byte `codec:"response"` //The UTF-8 encoded result of the getJwsResult() call of the SafetyNet API. This value is a JWS object
}

// Verify verifies Android SafetyNet Attestation Statement
// https://www.w3.org/TR/webauthn/#android-safetynet-attestation
func (a AndroidSafetyNetAttestationStmt) Verify() error {
	return nil
}

type AndroidSafetyNetAttestationResponse struct {
	Nonce                      string   `json:"nonce"`
	TimestampMs                int64    `json:"timestampMs"`
	ApkPackageName             string   `fjson:"apkPackageName"`
	ApkCertificateDigestSha256 []string `json:"apkCertificateDigestSha256"`
	ApkDigestSha256            string `json:"apkDigestSha256"`
	CtsProfileMatch            bool   `json:"ctsProfileMatch"`
	BasicIntegrity            bool   `json:"basicIntegrity"`
}

// ValidateClientData follows requirements from https://www.w3.org/TR/webauthn/#registering-a-new-credential
// x.x.x represents each criteria
// TODO challenge needs to be extracted from DB or some kind of data storage
// https://github.com/ugorji/go/issues/277
func (s ServerAuthenticatorAttestationResponse) Validate(challenge, origin, rpId string, requiresUserVerification bool) ([]byte, error) {
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
	clientDataHash := sha.Sum(nil) // This value will be used in 7.1.14

	// 7.1.8
	cborByte := make([]byte, base64.RawURLEncoding.DecodedLen(len(s.AttestationObject)))
	cborByte, err = base64.RawURLEncoding.DecodeString(s.AttestationObject)
	if err != nil {
		return nil, errors.Wrap(err, "failed base64 url decoding AttestationObject")
	}

	// TODO Need to find a way to decode ao.attStmt because it would vary based on ao.fmt
	ao := AttestationObject{AttStmt: AndroidSafetyNetAttestationStmt{}}
	if err := codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&ao); err != nil {
		return nil, errors.Wrap(err, "failed cbor decoding AttestationObject")
	}

	// 7.1.9 Verifying that the RP ID hash in auth Data is sha256 of RP ID
	// AuthData: https://www.w3.org/TR/webauthn/#authenticator-data
	if len(ao.AuthData) < 37 {
		return nil, errors.New("AuthData must be 37 bytes or more")
	}
	sha = sha256.New()
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

	// 7.1.12 Verifying the client extension
	// TODO Study and implement extension verification
	doesIncludeExtensions := flags & (1 << 7) >> 7 // https://www.w3.org/TR/webauthn/#sctn-extension-id
	if doesIncludeExtensions == 1 {}

	// 7.1.13 Determine the attestation statement
	switch ao.Fmt {
	// 7.1.14 Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.
	// 7.1.15 If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy.
	// 7.1.16 Assess the attestation trustworthiness using the outputs of the verification procedure in step 14
		// If self attestation was used, check if self attestation is acceptable under Relying Party policy.
		//  If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 15.
		// Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.
	// 7.1.19 If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.
	case "packed":
	case "tpm":
	case "android-key":
	case "android-safetynet": // https://www.w3.org/TR/webauthn/#android-safetynet-attestation
		// 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
		// TODO

		// 2) Verify that response is a valid SafetyNet response of version ver.
		// TODO Not quite sure what would be "valid SafetyNet response of version ver"

		// Response is actually in JWS format
		rawJWS := string(ao.AttStmt.(AndroidSafetyNetAttestationStmt).Response)
		token, err := jwt.ParseSigned(rawJWS)
		if err != nil {
			return nil, err
		}

		// 3) Verifying the nonce requires to retrieve response
		// But, due to go-jose restriction, we first need to retrieve a certificate
		// which actually required verifying certificate chain.
		// 4) Verify that the attestation certificate is issued to the hostname "attest.android.com"
		rootCerts := x509.NewCertPool()
		if ok := rootCerts.AppendCertsFromPEM([]byte(rootPEM)); !ok {
			return nil, errors.New("Failed to parse PEM encoded certificates")
		}

		opts := x509.VerifyOptions{
			Roots: rootCerts,
			DNSName: "attest.android.com",
		}

		// go-jose internally verify that attestationCert is issued to the hostname "attest.android.com"
		// attestationCert
		attestationCert, err := token.Headers[0].Certificates(opts)
		if err != nil {
			return nil, err
		}

		response := &AndroidSafetyNetAttestationResponse{}
		if err := token.Claims(attestationCert[0][0].PublicKey, response); err != nil {
			return nil, err
		}

		// 3) Verify that the nonce in the response is identical to the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
		nonceBase := append(ao.AuthData, clientDataHash...)
		sha = sha256.New()
		sha.Write(nonceBase)
		nonceBuffer := sha.Sum(nil)
		expectedNonce := base64.StdEncoding.EncodeToString(nonceBuffer)

		if response.Nonce != expectedNonce {
			errorMessage := "Nonce in Android SafetyNet Attestation Statement seems wrong\n"
			errorMessage += fmt.Sprintf("Expected %s, but was %s", expectedNonce, response.Nonce)
			return nil, errors.New(errorMessage)
		}

		// Verify that the ctsProfileMatch attribute in the payload of response is true
		if !response.CtsProfileMatch {
			return nil, errors.New("CtsProfileMatch must be true")
		}
	case "fido-u2f":
	case "none":
	}

	doesIncludeAttestedClientData := flags & (1 << 6) >> 6
	if doesIncludeAttestedClientData == 1 {
		//aaguid := ao.AuthData[37:53]
		//credentialIdLength := ao.AuthData[53:55]
		//credentialId := ao.AuthData[55:55+credentialIdLength[1]]
		// 7.17
		// TODO Check that the credentialId is not yet registered to any other user
		// 7.18
		// TODO Register user associating credentialId and credentialPublicKey
	}


	return nil, nil
}