package main

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
)

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
