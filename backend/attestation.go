package main

type AndroidSafetyNetAttestationResponsePayload struct {
	Nonce                      string   `json:"nonce"`
	TimestampMs                int64    `json:"timestampMs"`
	ApkPackageName             string   `json:"apkPackageName"`
	ApkCertificateDigestSha256 []string `json:"apkCertificateDigestSha256"`
	ApkDigestSha256            []string `json:"apkDigestSha256"`
}

type AndroidSafetyNetAttestationHeader struct {
	Alg string   `json:"alg"`
	X5C []string `json:"x5c"`
}