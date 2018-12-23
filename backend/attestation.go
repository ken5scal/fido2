package main

type AndroidSafetyNetAttestationResponse struct {
	Nonce                      string   `json:"nonce"`
	TimestampMs                int64    `json:"timestampMs"`
	ApkPackageName             string   `json:"apkPackageName"`
	ApkCertificateDigestSha256 []string `json:"apkCertificateDigestSha256"`
	ApkDigestSha256            string `json:"apkDigestSha256"`
	CtsProfileMatch            bool   `json:"ctsProfileMatch"`
	BasicIntegrity            bool   `json:"basicIntegrity"`
}