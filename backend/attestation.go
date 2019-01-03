package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"unicode/utf8"

	"crypto/ecdsa"

	"encoding/asn1"

	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
	"gopkg.in/square/go-jose.v2/jwt"
)

//============================================
// Attestation Object
//============================================

// Attestation Object
// https://www.w3.org/TR/webauthn/#generating-an-attestation-object
type AttestationObject struct {
	Fmt      string          `codec:"fmt"`
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

// AndroidSafetyNetAttestationResponse
// https://developer.android.com/training/safetynet/attestation
type AndroidSafetyNetAttestationResponse struct {
	Nonce                      string   `json:"nonce"`
	TimestampMs                int64    `json:"timestampMs"`
	ApkPackageName             string   `json:"apkPackageName"`
	ApkCertificateDigestSha256 []string `json:"apkCertificateDigestSha256"`
	ApkDigestSha256            string   `json:"apkDigestSha256"`
	CtsProfileMatch            bool     `json:"ctsProfileMatch"`
	BasicIntegrity             bool     `json:"basicIntegrity"`
	Error                      string   `json:"error"`
}

// AndroidKeyAttestationStmt
// https://www.w3.org/TR/webauthn/#android-key-attestation
type AndroidKeyAttestationStmt struct {
	Algorithm int      `codec:"alg"`
	Signature []byte   `codec:"sig"`
	X5c       [][]byte `codec:"x5c"` // x5c[0] = credCert, x5c[1...] = caCerts
}

// Verify verifies Android Key Attestation Statement
// https://www.w3.org/TR/webauthn/#android-key-attestation
func (a AndroidKeyAttestationStmt) Verify() error {
	return nil
}

type AndroidKeyAttestationExtensionSchema struct {
	AttestationVersion int `asn1`
	// Need Help
	// AttestationSecurityLevelは0,1なEnumの値であるが、それ専用のEnumを割り与えてもDecodeできなかった
	AttestationSecurityLevel asn1.Enumerated `asn1:"enum"` // 0-> Software, 1-> TEE
	KeymasterVersion         int             `asn1`
	KeymasterSecurityLevel   asn1.Enumerated `asn1:"enum"`
	AttestationChallenge     []byte          `asn1`
	UniqueId                 []byte          `asn1`
	SoftwareEnforced         asn1.RawValue   `asn1`
	TeeEnforced              asn1.RawValue   `asn1`
}

type AndroidKeyAttestationAuthorizationList struct {
	//Purpose                   []int       `asn1:"optional,set"` //1
	//Algorithm                 int         `asn1:"optional"`     //2
	//KeySize                   int         `asn1:"optional"`     //3
	//Digest                    []int       `asn1:"optional,set"` //5
	//Padding                   []int       `asn1:"optional,set"` //6
	//EcCurve                   int         `asn1:"optional"`     //10
	//RsaPublicExponent         int         `asn1:"optional"`     //200
	ActiveDateTime            int `asn1:"tag:400,explicit"` //400
	OriginationExpireDateTime int `asn1:"tag:401,explicit"` //401
	UsageExpireDateTime       int `asn1:"tag:402,explicit"` //402
	//NoAuthRequired            int         `asn1:"optional"` //503 //Because this can be nil
	//UserAuthType              int         `asn1:"optional"` //504
	//AuthTimeout               int         `asn1:"optional"` //505
	//AllowWhileOnBody          int         `asn1:"optional"` //506 //Because this can be nil
	//AllApplications           int         `asn1:"optional"` //600 Because this can be nil
	//ApplicationId             []byte      `asn1:"optional"` //601
	CreationDateTime int `asn1:"tag:701,explicit"` //701
	//Origin                   int         `asn1:"optional"` //702
	//RollbackResistant        int         `asn1:"optional"` //703 //ExplicitNullOption?
	//RootOfTrust              RootOfTrust `asn1:"optional"` //704
	//OsVersion                int         `asn1:"optional"` //705
	//OsPatchLevel             int         `asn1:"optional"` //706
	//AttestationChallenge     int         `asn1:"optional"` //708
	AttestationApplicationId []byte `asn1:"tag:709,explicit"` //709
	//attestationApplicationId   [709] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	//attestationIdBrand         [710] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	//attestationIdDevice        [711] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	//attestationIdProduct       [712] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	//attestationIdSerial        [713] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	//attestationIdImei          [714] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	//attestationIdMeid          [715] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	//attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	//attestationIdModel         [717] EXPLICIT OCTET_STRING OPTIONAL, # KM3
}

type RootOfTrust struct {
	VerifiedBootKey   []byte          `asn1:"optional"`
	DeviceLocked      bool            `asn1:"optional"`
	VerifiedBootState asn1.Enumerated `asn1:"optional,enum"` // 0 -> Verified, 1 -> SelfSigned, 2 -> Unverified, 3 -> Failed
}

type AuthorizationList struct {
	Purpose                   asn1.RawValue `asn1:"set,optional"`
	Algorithm                 asn1.RawValue `asn1:"explicit,optional"`
	KeySize                   asn1.RawValue `asn1:"optional"`
	Digest                    asn1.RawValue `asn1:"set,optional"`
	Padding                   asn1.RawValue `asn1:"set,optional"`
	EcCurve                   asn1.RawValue `asn1:"optional"`
	RsaPublicExponent         asn1.RawValue `asn1:"optional"`
	ActiveDateTime            asn1.RawValue `asn1:"optional"`
	OriginationExpireDateTime asn1.RawValue `asn1:"optional"`
	UsageExpireDateTime       asn1.RawValue `asn1:"optional"`
	NoAuthRequired            asn1.RawValue `asn1:"optional"`
	UserAuthType              asn1.RawValue `asn1:"optional"`
	AuthTimeout               asn1.RawValue `asn1:"optional"`
	AllowWhileOnBody          asn1.RawValue `asn1:"optional"`
	AllApplications           asn1.RawValue `asn1:"optional"`
	ApplicationId             asn1.RawValue `asn1:"optional"`
	CreationDateTime          asn1.RawValue `asn1:"optional"`
	Origin                    asn1.RawValue `asn1:"optional"`
	RollbackResistant         asn1.RawValue `asn1:"optional"`
	RootOfTrust               asn1.RawValue `asn1:"optional"`
	OsVersion                 asn1.RawValue `asn1:"optional"`
	OsPatchLevel              asn1.RawValue `asn1:"optional"`
	AttestationChallenge      asn1.RawValue `asn1:"optional"`
	AttestationApplicationId  asn1.RawValue `asn1:"optional"`
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
	ao := AttestationObject{AttStmt: AndroidKeyAttestationStmt{}}
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
	if doesIncludeExtensions == 1 {
	}

	// They will be used later
	doesIncludeAttestedClientData := flags & (1 << 6) >> 6
	//aaguid := ao.AuthData[37:53]
	credentialIdLength := ao.AuthData[53:55]
	//credentialId := ao.AuthData[55 : 55+credentialIdLength[1]]

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
	case "android-key": // https://www.w3.org/TR/webauthn/#android-key-attestation
		stmt := ao.AttStmt.(AndroidKeyAttestationStmt)

		// 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
		// TODO

		// 2) Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the public key in the first certificate in x5c with the algorithm specified in alg
		signed := append(ao.AuthData, clientDataHash...)

		leafCert, err := x509.ParseCertificate(stmt.X5c[0])
		if err != nil {
			return nil, errors.New("Failed to parse PEM encoded certificates")
		}

		if err := leafCert.CheckSignature(leafCert.SignatureAlgorithm, signed, stmt.Signature); err != nil {
			return nil, errors.Wrap(err, "Failed to verify a signature over the concatenation of authenticatorData and clientDataHash using the public key in the first certificate in x5c with the algorithm specified in alg")
		}

		// 3) Verify that the public key in the first certificate in in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData
		//TODO This is ignoring the fact that cosePublicKeyInByte is not fixed length while possibly having extension Data followed by cosePublicKeyInByte
		//NEED HELP
		cosePublicKeyInByte := ao.AuthData[55+credentialIdLength[1]:]
		var coseKey map[int]interface{}
		if err := codec.NewDecoderBytes(cosePublicKeyInByte, new(codec.CborHandle)).Decode(&coseKey); err != nil {
			return nil, errors.Wrap(err, "failed cbor decoding AttestationObject")
		}

		// COSE Key Common Parameters: https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
		// COSE KEY Types: https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
		switch pub := leafCert.PublicKey.(type) { // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
		case *ecdsa.PublicKey:
			// TODO Not Quite sure if this is the right approach
			isOnCurve := pub.IsOnCurve(
				//-2 and -3 comes EC2 Key Types -> https://tools.ietf.org/html/rfc8152#section-13.1
				new(big.Int).SetBytes(coseKey[-2].([]byte)), //x
				new(big.Int).SetBytes(coseKey[-3].([]byte))) //y
			if !isOnCurve {
				return nil, errors.New("The public key in the leaf certificate does not match the `credentialPublicKey` in the `attestedCredentialData` in `authenticatorData`.")
			}
		}

		// 4) Verify that in the attestation certificate extension data
		for _, v := range leafCert.Extensions {
			if v.Id.Equal(androidKeyAttestationOID) {
				var extensions AndroidKeyAttestationExtensionSchema
				if _, err := asn1.Unmarshal(v.Value, &extensions); err != nil {
					return nil, errors.Wrap(err, "Failed to decode certificate extension into asn1 sequence")
				}
				fmt.Println(fmt.Sprintf("%x", v.Value))
				fmt.Println(extensions.AttestationVersion)
				fmt.Println(extensions.KeymasterVersion)
				// 4-1) The value of the attestationChallenge field is identical to clientDataHash.
				if !bytes.Equal(extensions.AttestationChallenge, clientDataHash) {
					return nil, errors.New("Failed to verify that the value of the attestationChallenge field is identical to clientDataHash")
				}

				fmt.Println(extensions.SoftwareEnforced)
				fmt.Println(extensions.TeeEnforced)
				fmt.Println(fmt.Sprintf("%x", extensions.SoftwareEnforced.FullBytes))
				fmt.Println(fmt.Sprintf("%x", extensions.TeeEnforced.FullBytes))
				// 4-2) The AuthorizationList.allApplications field is not present, since PublicKeyCredential MUST be bound to the RP ID.
				fmt.Println("=================================================")
				fmt.Println("============= Sw Enforced Checking ==============")
				fmt.Println("=================================================")

				fmt.Println("============= fuga ==============")
				var fuga AuthorizationList
				if _, err := asn1.Unmarshal(extensions.SoftwareEnforced.FullBytes, &fuga); err != nil {
					return nil, errors.Wrap(err, "bbbbbbbb")
				}
				fmt.Println(fuga)

				fmt.Println("============= hoge ==============")
				var hoge AndroidKeyAttestationAuthorizationList
				if _, err := asn1.Unmarshal(extensions.SoftwareEnforced.FullBytes, &hoge); err != nil {
					return nil, errors.Wrap(err, "bbbbbbbb")
				}
				fmt.Println(hoge)
				//fmt.Println(fmt.Sprintf("1: %v:", hoge.Purpose))
				//fmt.Println(fmt.Sprintf("2: %v:", hoge.Algorithm))
				//fmt.Println(fmt.Sprintf("3: %v:", hoge.KeySize))
				//fmt.Println(fmt.Sprintf("5: %v:", hoge.Digest))
				//fmt.Println(fmt.Sprintf("10: %v:", hoge.EcCurve))
				fmt.Println(fmt.Sprintf("400: %v:", hoge.ActiveDateTime))
				fmt.Println(fmt.Sprintf("401: %v:", hoge.OriginationExpireDateTime))
				fmt.Println(fmt.Sprintf("402: %v:", hoge.UsageExpireDateTime))
				//fmt.Println(fmt.Sprintf("504: %v:", hoge.UserAuthType))
				//fmt.Println(fmt.Sprintf("505: %v:", hoge.AuthTimeout))
				fmt.Println(fmt.Sprintf("701: %v:", hoge.CreationDateTime))
				//fmt.Println(fmt.Sprintf("702: %v:", hoge.Origin))
				fmt.Println(fmt.Sprintf("709: %v:", hoge.AttestationApplicationId))

				fmt.Println("==================================================")
				fmt.Println("============= Tee Enforced Checking ==============")
				fmt.Println("==================================================")
				if _, err := asn1.Unmarshal(extensions.TeeEnforced.FullBytes, &hoge); err != nil {
					return nil, errors.Wrap(err, "aaaaaaaaaa")
				}

				fmt.Println("============= hoge ==============")
				fmt.Println(hoge)
				//fmt.Println(fmt.Sprintf("1: %v:", hoge.Purpose))
				//fmt.Println(fmt.Sprintf("2: %v:", hoge.Algorithm))
				//fmt.Println(fmt.Sprintf("3: %v:", hoge.KeySize))
				//fmt.Println(fmt.Sprintf("5: %v:", hoge.Digest))
				//fmt.Println(fmt.Sprintf("10: %v:", hoge.EcCurve))
				fmt.Println(fmt.Sprintf("400: %v:", hoge.ActiveDateTime))
				fmt.Println(fmt.Sprintf("401: %v:", hoge.OriginationExpireDateTime))
				fmt.Println(fmt.Sprintf("402: %v:", hoge.UsageExpireDateTime))
				//fmt.Println(fmt.Sprintf("504: %v:", hoge.UserAuthType))
				//fmt.Println(fmt.Sprintf("505: %v:", hoge.AuthTimeout))
				fmt.Println(fmt.Sprintf("701: %v:", hoge.CreationDateTime))
				//fmt.Println(fmt.Sprintf("702: %v:", hoge.Origin))
				fmt.Println(fmt.Sprintf("709: %v:", hoge.AttestationApplicationId))

				if _, err := asn1.Unmarshal(extensions.TeeEnforced.FullBytes, &fuga); err != nil {
					return nil, errors.Wrap(err, "aaaaaaaaaa")
				}
				fmt.Println("============= fuga ==============")
				fmt.Println(fuga)

				//fmt.Println(extensions.TeeEnforced)
				//if extensions.SoftwareEnforced[0].AllApplications != nil || extensions.TeeEnforced[0].AllApplications != nil {
				//	return nil, errors.New("AuthorizationList.allApplications field is supposed to be not present")
				//}

				// 4-3) The value in the AuthorizationList.origin field is equal to KM_TAG_GENERATED.
				// 4-4) The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
			}
		}
		if !false {
			return nil, errors.New("Not finished to Verify that in the attestation certificate extension data")
		}

		return nil, nil
	case "android-safetynet": // https://www.w3.org/TR/webauthn/#android-safetynet-attestation
		fmt.Println(ao.AttStmt)
		// 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
		// TODO

		// 2) Verify that response is a valid SafetyNet response of version ver.
		// TODO Not quite sure what would be "valid SafetyNet response of version ver"
		// https://developer.android.com/training/safetynet/attestation#check-gps-version

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
		if ok := rootCerts.AppendCertsFromPEM([]byte(androidSafetyNetAuthenticatorRootPEM)); !ok {
			return nil, errors.New("Failed to parse PEM encoded certificates")
		}

		opts := x509.VerifyOptions{
			Roots:   rootCerts,
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

	doesIncludeAttestedClientData = flags & (1 << 6) >> 6
	if doesIncludeAttestedClientData == 1 {
		// 7.17
		// TODO Check that the credentialId is not yet registered to any other user
		// 7.18
		// TODO Register user associating credentialId and credentialPublicKey
	}

	return nil, nil
}

type Tsr struct {
	Result struct {
		Code   int
		Detail struct{ Message string }
	}
	SignedData struct {
		OID  asn1.ObjectIdentifier
		Zero struct {
			Seq struct {
				Int int
				Set struct {
					InnerSeq struct {
						OID asn1.ObjectIdentifier
					}
				} `asn1:"set"`
			}
		} `asn1:"tag:0"`
	}
}
