package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
	"unicode/utf8"
)

const androidAttestationCertSubjectName = "attest.android.com"

// ServerPublicKeyCredentialCreationOptionsRequest
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsrequest
type ServerPublicKeyCredentialCreationOptionsRequest struct {
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`

	// https://w3c.github.io/webauthn/#authenticatorSelection
	AuthenticatorSelectionCriteria struct {
		RequireResidentKey bool `json:"residentKey"` // default = false
		//https://w3c.github.io/webauthn/#attachment
		//It is Enum with either value {"platform","cross-platform"}
		AuthenticationAttachment string `json:"authenticatorAttachment,omitempty"` // no default
		//https://w3c.github.io/webauthn/#userVerificationRequirement
		//It is Enum with either value {"required","preferred","discouraged"}
		UserVerificationRequirement string `json:"userVerification"` // default = preferred
	} `json:"authenticatorSelection,omitempty"`

	//https://w3c.github.io/webauthn/#enumdef-attestationconveyancepreference
	//It is Enum with either value {"none","indirect","direct"}
	AttestationConveyancePreference AttestationConveyancePreference `json:"attestation,omitempty"` // default="none"
}

func (s ServerPublicKeyCredentialCreationOptionsRequest) validate() error {
	if s.UserName != "" && s.DisplayName != "" {
		return nil
	}
	return errors.New("Both userName and displayName must be present")
}

type AuthenticatorAttachment int

const (
	_ AuthenticatorAttachment = iota
	Platform
	CrossPlatform
)

func (a AuthenticatorAttachment) String() string {
	return toStringAA[a]
}

var toStringAA = map[AuthenticatorAttachment]string{
	Platform:      "platform",
	CrossPlatform: "cross-platform",
}

func (a *AuthenticatorAttachment) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(a.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (a *AuthenticatorAttachment) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	switch j {
	case "platform":
		*a = Platform
	case "cross-platform":
		*a = CrossPlatform
	default:
		return errors.New("Invalid Authenticator Attachment. Must be either 'platform' or 'cross-platform'")
	}
	return nil
}

type UserVerificationRequirement int

const (
	_ UserVerificationRequirement = iota
	Required
	Preferred
	Discouraged
)

func (u UserVerificationRequirement) String() string {
	return toStringUV[u]
}

var toStringUV = map[UserVerificationRequirement]string{
	Required:    "required",
	Preferred:   "preferred",
	Discouraged: "discouraged",
}

func (u *UserVerificationRequirement) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(toStringUV[*u])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (u *UserVerificationRequirement) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	switch j {
	case "required":
		*u = Required
	case "discouraged":
		*u = Discouraged
	case "preferred":
		*u = Preferred
	default:
		*u = Preferred //Preferred is the default value
	}
	return nil
}

type AttestationConveyancePreference int

const (
	_ AttestationConveyancePreference = iota
	None
	Indirect
	Direct
)

func (a AttestationConveyancePreference) String() string {
	return toString[a]
}

var toString = map[AttestationConveyancePreference]string{
	None:     "none",
	Indirect: "indirect",
	Direct:   "direct",
}

func (a *AttestationConveyancePreference) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(toString[*a])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (a *AttestationConveyancePreference) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	switch j {
	case "indirect":
		*a = Indirect
	case "direct":
		*a = Direct
	case "none":
		*a = None
	default:
		*a = None // None is default value
	}
	return nil
}

// ServerPublicKeyCredentialCreationOptionsResponse
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsresponse
type ServerPublicKeyCredentialCreationOptionsResponse struct {
	// Required
	Challenge                   string `json:"challenge"`
	PublicKeyCredentialRpEntity struct {
		Name string `json:"name"`
	} `json:"rp"`
	ServerPublicKeyCredentialUserEntity struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	PublicKeyCredentialParameters []PubKeyParam `json:"pubKeyCredParams"`

	// Optional
	Timeout                        uint64              `json:"timeout,omitempty"`
	ExcludeCredentials             []ExcludeCredential `json:"excludeCredentials,omitempty"`
	AuthenticatorSelectionCriteria struct {
		ResidentKey             bool   `json:"residentKey"`
		AuthenticatorAttachment string `json:"authenticatorAttachment"`
		UserVerification        string `json:"userVerification"`
	} `json:"authenticatorSelection,omitempty"`
	Attestation string `json:"attestation,omitempty"` // default="none"
	// AuthenticationExtensionsClientInputs  struct{} //TODO 一旦無視
}

type PubKeyParam struct {
	Type string `json:"type"` //今は固定 publick-key: https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype
	Alg  int    `json:"alg"`  //https://w3c.github.io/webauthn/#alg-identifier
}

type ExcludeCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ServerPublicKeyCredential
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential
type ServerPublicKeyCredential struct {
	// This attribute is inherited from Credential, though ServerPublicKeyCredential overrides it with base64url encoding of the authenticator credId
	ID string `json:"id"`
	// same as id
	RawID string `json:"rawId"`
	// a dictionary defined as ServerAuthenticatorAttestationResponse or by ServerAuthenticatorAttestationResponse
	AuthenticatorAttestationResponse ServerAuthenticatorAttestationResponse `json:"response"`
	// This attribute is inherited from Credential, though ServerPublicKeyCredential overrides it with "public-key"
	Type string `json:"type"` // public-key固定
	// ???  map containing extension identifier, which contain client extension output entries produced by the extension’s client extension processing
	AuthenticationExtensionsClientOutputs struct{} `json:"getClientExtensionResults"`
}

type ServerAuthenticatorAttestationResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`    //base64url encoded clientDataJSON buffer
	AttestationObject string `json:"attestationObject"` //base64url encoded attestationObject buffer
}

// ClientDataJSON
// https://www.w3.org/TR/webauthn/#sec-client-data
type ClientData struct {
	Type        string       `json:"type"`
	Challenge   string       `json:"challenge"`
	Origin      string       `json:"origin"`
	TokenBiding TokenBinding `json:"tokenBinding"`
}

// TokenBinding
// https://www.w3.org/TR/webauthn/#sec-client-data
type TokenBinding struct {
	TokenBindingStatus TokenBindingStatus `json:"status"`
	ID                 string             `json:"id"`
}

type TokenBindingStatus int

const (
	_ TokenBindingStatus = iota
	Present
	Supported
	NotSupported //?Not really shown in https://www.w3.org/TR/webauthn/#sec-client-data
)

// Validate
// WebAuthN: 7.1
// https://www.w3.org/TR/webauthn/#registering-a-new-credential
var hashOfClientData string

func (s ServerAuthenticatorAttestationResponse) Validate(challenge, origin string) error {
	clientDataInBytes, err := base64.RawURLEncoding.DecodeString(s.ClientDataJSON)
	if err != nil {
		return errors.New("Failed Decoding ClientDataJSON")
	}

	// 7.1.1
	// https://www.w3.org/TR/webauthn/#registering-a-new-credential
	if utf8.Valid(clientDataInBytes) {
		return errors.New("Invalid json")
	}

	// 7.1.2
	var clientData ClientData
	if err := json.Unmarshal(clientDataInBytes, &clientData); err != nil {
		return errors.New("Failed Unmarshal ClientDataJSON")
	}

	// 7.1.3
	// TODO make this enum
	if clientData.Type != "webauthn.create" {
		return errors.New("ClientData type is not 'webauthn.create'")
	}

	// 7.1.4
	if clientData.Challenge != challenge {
		return errors.New("ClientData challenge is not same as the one from ServerPublicKeyCredentialCreationOptionsResponse")
	}

	// 7.1.5
	// given a Relying Party whose origin is https://login.example.com:1337, then the following RP IDs are valid: login.example.com (default) and example.com, but not m.login.example.com and not com
	// https://www.w3.org/TR/webauthn/#webauthn-relying-party
	// TODO Implement Correctly
	if clientData.Origin != origin {
		return errors.New("ClientData challenge is not same as the origin")
	}

	// 7.1.6
	// TODO Skip for now (Got No Idea)
	//if clientData.TokenBiding.TokenBindingStatus == {
	//
	//}

	// 7.1.7
	sha := sha256.New()
	sha.Write(clientDataInBytes)
	//hashOfClientData := hex.EncodeToString(sha.Sum(nil))

	// 7.1.8 CBOR Decoding
	cborByte := make([]byte, base64.RawURLEncoding.DecodedLen(len(s.AttestationObject)))
	cborByte, err = base64.RawURLEncoding.DecodeString(s.AttestationObject)
	if err != nil {
		return errors.Wrap(err, "failed base64 url decoding AttestationObject")
	}

	// TODO Not quite sure how to extract AttObj based on not yet decoded Format
	ao := AttestationObject{}
	//var ao interface{}
	if err := codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&ao); err != nil {
		return errors.Wrap(err, "failed cbor decoding AttestationObject")
	}

	// 7.1.9 Verifying that the RP ID hash in auth Data is sha256 of RP ID
	// AuthData: https://www.w3.org/TR/webauthn/#authenticator-data
	if len(ao.AuthData) < 37 {
		return errors.New("AuthData must be 37 bytes or more")
	}
	sha.Write([]byte(rp))
	rpIdHash := hex.EncodeToString(sha.Sum(nil))
	if rpIdHash != hex.EncodeToString(ao.AuthData[0:32]) {
		return errors.New("RP ID Hash in authData is not SHA-256 hash of the RP ID")
	}

	// 7.1.10 Verify UP bit of the flags in authData is set
	// 7.1.11 Verify UV bit of the flags in authData is set IF it is required
	flags := ao.AuthData[32]
	up := flags & (1 << 0) >> 0
	uv := flags & (1 << 2) >> 2
	//attestedClientData := flags & (1 << 6) >> 6
	doesIncludeExtensions := flags & (1 << 7) >> 7

	if up == 0 {
		// https://www.w3.org/TR/webauthn/#test-of-user-presence
		return errors.New("Requires user interaction with an authenticator (Not necessary has to be verification)")
	}

	if requiresUserVerification && uv == 0 {
		return errors.New("Requires user verification by an authenticator.")
	}

	// 7.1.12 Verifying the client extension
	if doesIncludeExtensions == 1 {
		// TODO Study and implement extetion verification
		// https://www.w3.org/TR/webauthn/#sctn-extension-id
	}

	// 7.1.13 Determine the attestation statement
	switch ao.Fmt {
	case "packed":
	case "tpm":
	case "android-key":
	case "android-safetynet":
	case "fido-u2f":
	case "none":
	}

	return nil
}

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

// AndroidKeyAttestation
// https://www.w3.org/TR/webauthn/#android-key-attestation
type AndroidKeyAttestationStmt struct {
	Sig []byte   `codec:"sig"`
	X5c [][]byte `codec:"x5c"`
}

func (a AndroidKeyAttestationStmt) Verify() bool {
	return false
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
