package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ugorji/go/codec"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"crypto/x509"
	"gopkg.in/square/go-jose.v2/jwt"
	"errors"
)

var rp = "Example Corporation"
var uuid = "S3932ee31vKEC0JtJMIQ"
var userName = "kengoscal@gmail.com"
var displayName = "ken5scal"
var requiresUserVerification = true
var challenge string
var config Config

type Config struct {
	Port   uint
	Origin string
	Debug  bool
}

func init() {
	//if _, err := toml.DecodeFile("config.toml", &config); err != nil {
	//	log.Fatal().Err(err).Msg("Failed reading config")
	//}
	config.Debug = true
	config.Port = 8080
	config.Origin = "example.com"

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if config.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Logger = log.With().Caller().Logger().Output(zerolog.ConsoleWriter{Out: os.Stdout})
}

func main() {
	var clientData ClientData
	androidSafetyNetClientDataJSON := "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
	clientDataInBytes, err := base64.RawURLEncoding.DecodeString(androidSafetyNetClientDataJSON)
	if err != nil {
		log.Error().Err(err).Msg("failed base64 decoding")
	}

	if err := json.Unmarshal(clientDataInBytes, &clientData); err != nil {
		log.Error().Err(err).Msg("failed unmarshalling json")
	}
	fmt.Println(clientData.Origin)
	fmt.Println(clientData.Type)
	fmt.Println(clientData.Challenge)
	fmt.Println(clientData.TokenBiding)

	packedAttestationObj := "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIsK0Wr9tmud-waIYoQw20UWi7DL_gDx_PNG3PB57eHLAiEAtRyd-4JI2pCVX-dDz4mbHc_AkvC3d_4qnBBa3n2I_hVjeDVjg1kCRTCCAkEwggHooAMCAQICEBWfe8LNiRjxKGuTSPqfM-IwCgYIKoZIzj0EAwIwSTELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMRswGQYDVQQDDBJGZWl0aWFuIEZJRE8yIENBLTEwIBcNMTgwNDExMDAwMDAwWhgPMjAzMzA0MTAyMzU5NTlaMG8xCzAJBgNVBAYTAkNOMR0wGwYDVQQKDBRGZWl0aWFuIFRlY2hub2xvZ2llczEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEdMBsGA1UEAwwURlQgQmlvUGFzcyBGSURPMiBVU0IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASABnVcWfvJSbAVqNIKkliXvoMKsu_oLPiP7aCQlmPlSMcfEScFM7QkRnidTP7hAUOKlOmDPeIALC8qHddvTdtdo4GJMIGGMB0GA1UdDgQWBBR6VIJCgGLYiuevhJglxK-RqTSY8jAfBgNVHSMEGDAWgBRNO9jEZxUbuxPo84TYME-daRXAgzAMBgNVHRMBAf8EAjAAMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEEI4MkVENzNDOEZCNEU1QTIwCgYIKoZIzj0EAwIDRwAwRAIgJEtFo76I3LfgJaLGoxLP-4btvCdKIsEFLjFIUfDosIcCIDQav04cJPILGnPVPazCqfkVtBuyOmsBbx_v-ODn-JDAWQH_MIIB-zCCAaCgAwIBAgIQFZ97ws2JGPEoa5NI-p8z4TAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQxMDAwMDAwMFoYDzIwMzgwNDA5MjM1OTU5WjBJMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxGzAZBgNVBAMMEkZlaXRpYW4gRklETzIgQ0EtMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5-YAnswRZlzKD6w-lv5Qg7lW1XJRHrWzL01mc5V91n2LYXNR3_S7mA5gupuTO5mjQw8xfqIRMHVr1qB3TedY-jZjBkMB0GA1UdDgQWBBRNO9jEZxUbuxPo84TYME-daRXAgzAfBgNVHSMEGDAWgBTRoZhNgX_DuWv2B2e9UBL-kEXxVDASBgNVHRMBAf8ECDAGAQH_AgEAMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEA-3-j0kBHoRFQwnhWbSHMkBaY7KF_TztINFN5ymDkwmUCIQDrCkPBiMHXvYg-kSRgVsKwuVtYonRvC588qRwpLStZ7FkB3DCCAdgwggF-oAMCAQICEBWfe8LNiRjxKGuTSPqfM9YwCgYIKoZIzj0EAwIwSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTAgFw0xODA0MDEwMDAwMDBaGA8yMDQ4MDMzMTIzNTk1OVowSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ3wCm47zF9RMtW-pPlkEHTVTLfSYBlsidz7zOAUiuV6k36PvtKAI_-LZ8MiC9BxQUfUrfpLY6klw344lwLq7POjQjBAMB0GA1UdDgQWBBTRoZhNgX_DuWv2B2e9UBL-kEXxVDAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEAt7E9ZQYxnhfsSk6c1dSmFNnJGoU3eJiycs2DoWh7-IoCIA9iWJH8h-UOAaaPK66DtCLe6GIxdpIMv3kmd1PRpWqsaGF1dGhEYXRhWOSVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EEAAAABQjgyRUQ3M0M4RkI0RTVBMgBgsL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401rpQECAyYgASFYIFkdweEE6mWiIAYPDoKz3881Aoa4sn8zkTm0aPKKYBvdIlggtlG32lxrang8M0tojYJ36CL1VMv2pZSzqR_NfvG88bA"
	//u2fAttestationObj := "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAO-683ISJhKdmUPmVbQuYZsp8lkD7YJcInHS3QOfbrioAiEAzgMJ499cBczBw826r1m55Jmd9mT4d1iEXYS8FbIn8MpjeDVjgVkCSDCCAkQwggEuoAMCAQICBFVivqAwCwYJKoZIhvcNAQELMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAqMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxNDMyNTM0Njg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESzMfdz2BRLmZXL5FhVF-F1g6pHYjaVy-haxILIAZ8sm5RnrgRbDmbxMbLqMkPJH9pgLjGPP8XY0qerrnK9FDCaM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCwYJKoZIhvcNAQELA4IBAQCsFtmzbrazqbdtdZSzT1n09z7byf3rKTXra0Ucq_QdJdPnFhTXRyYEynKleOMj7bdgBGhfBefRub4F226UQPrFz8kypsr66FKZdy7bAnggIDzUFB0-629qLOmeOVeAMmOrq41uxICn3whK0sunt9bXfJTD68CxZvlgV8r1_jpjHqJqQzdio2--z0z0RQliX9WvEEmqfIvHaJpmWemvXejw1ywoglF0xQ4Gq39qB5CDe22zKr_cvKg1y7sJDvHw2Z4Iab_p5WdkxCMObAV3KbAQ3g7F-czkyRwoJiGOqAgau5aRUewWclryqNled5W8qiJ6m5RDIMQnYZyq-FTZgpjXaGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABABo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IiraUBAgMmIAEhWCA1c9AIeH5sN6x1Q-2qR7v255tkeGbWs0ECCDw35kJGBCJYIBjTUxruadjFFMnWlR5rPJr23sBJT9qexY9PCc9o8hmT"
	attestationObj := "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgRvfOaUcMVmHqrKzXSH2Inb4PIshESObwuPrtTS_W3RMCICF_qfvwZhDRF8bqiNGYty2iXcOxY8Tgi7TgQJHZqi4wY3g1Y4FZAlMwggJPMIIBN6ADAgECAgQ8aClNMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAxMS8wLQYDVQQDDCZZdWJpY28gVTJGIEVFIFNlcmlhbCAyMzkyNTczNDgxMTExNzkwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL3fZ5Pbd5TDUDFx7SxNRUrZc2Z1Gki6pdn5tWo6IIF5a07fK817knoUkxD7xGhHb_xXkql9ti-gKGvGoyACDmOjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMA0GCSqGSIb3DQEBCwUAA4IBAQCqwA1RCX7sFaSGs3m8xINA-GfTly7Oamf7pHDjYMZEWfCtOELT_wgeceqJU5cbI_klwK0AwkcxGFIG8LOpGSn7kbdmtT_hM1Iqg1i40SC0q_t_6O8ke2T_xqYhSsHZvnM2_eDzqBg_k0tSGHX14_eJgK-XClseBCo4dtdLqL7v6S3S43PMZEHIlK182aT0fa09pP6vR5GYR1PjWgic5Mvj08g26tCip86lYVrX5EgQhsN3s2ZE0vuZa7zimyGtuJX3k4LuxUk-TsEzwhZ_B3H1mTFzEg_yjVPogaiXQMEyzzw0aCy7z05dvcHggCIfh1KZgUHdFJbXDzqwPyxbwH-taGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAimCIoe8U_N9M1rTGeCqJ96TAu5uqSPa7YUzdh7qq-AdJlnBl8NwCpu2-sNj9UIVH5rAjX_RXlSGTGWKexKIZXKUBAgMmIAEhWCB7XpGVxTYo6jtkxB7sBR4Af_YM0GvInN5V7IvUIilN2yJYINphegJ6kNET_VIp0QOxssW8xxUFEgg5ic3HXmoGg4fS"
	base64Url := base64.RawURLEncoding
	cborByte := make([]byte, base64Url.DecodedLen(len(attestationObj)))
	cborByte, err = base64Url.DecodeString(attestationObj)
	if err != nil {
		log.Error().Err(err).Msg("failed base64 decoding")
	}

	var m2 map[string]interface{}

	fmt.Println("================ Packed attestation ===============")
	attestationObj = packedAttestationObj
	cborByte = make([]byte, base64Url.DecodedLen(len(attestationObj)))
	cborByte, err = base64Url.DecodeString(attestationObj)
	err = codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&m2)
	if err != nil {
		log.Error().Err(err).Msg("failed decoding cbor")
	}
	fmt.Printf("decoded type : %T\n", m2)
	fmt.Printf("decoded value: %v\n", m2)

	fmt.Println("================ Android SafetyNet attestation ===============")
	attestationObj = "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE0MzY2MDE5aHJlc3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVVkpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXbkJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROTlZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4MVNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSVzFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQlJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPRGh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKNVJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTek5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSbXRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3MGVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQzh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoVFRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZMEpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1aU1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RNE1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LMmRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaaVRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNRm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFNWFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNbTFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiVFpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4UldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTRzVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWVGw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daVVlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTVVpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKRlIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlVTFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWNFZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQlVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRVEJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0UmtkbVkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKNVFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UVUpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoSFFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRVkZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkMGNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkbGt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1cVFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGSGIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVRVZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5SllYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SSGh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSNmN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tORGIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmUS5leUp1YjI1alpTSTZJa2tyVW5GVE1IVnZlSEpKYld0MkwxTXJOa3hZVlhwMlNrVTJRVkZ5UkRGNGJEQjVTM2Q0TW0xS1NUUTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOREV6TXpZM01qazVNekFzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbVZSWXl0MmVsVmpaSGd3UmxaT1RIWllTSFZIY0VRd0sxSTRNRGR6VlVWMmNDdEtaV3hsV1ZwemFVRTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5XTGV3N1FqemM2QTZHeVZfck1VRlhSZzEyVEtSb0ROLXJhSG9NSzY3SGdCbk5Yc0QtOUtjaG1TVFpBWWZfLXFKZE1wN1BhYml4VnF4ZDdDQzFxTFBPaUZYLVd5RGJzZlltNmRabFFiODhSd2R6LVEyUVJfTDFCN3NTaURlV1lTeDZmMm10MlQ0WXQ4MjNGNHNGYk8zVlpXM1RacmRRLXBlMVFWMEZYTTRUQ1dXbWVVRUUyWEJmaFVYbHJ5MEFicWhnQUNsWWFGcG8xdUhXUjhEOFkweDhtUDFocmVTMUtNN2NfT01lc1E5dl9mdlBETUE0SEUtYlpZbHZrRVV2VmFCeFpWVzB2SXN4eWxiWllSNVMxSjIwSXRPLV9kSDFERWRkY1kzcmc3bzd6RlJGSGFnd0QyN3dCMzlCTmk4cVNVcG1heEk1VWhrNE04X3BDSWtmLXBwaUFoYXV0aERhdGFYxZVpCI8ezuMjKVQDXb0Q18rjkTBaJ1G1WbuP18uyKb3URQAAAAAAAAAAAAAAAAAAAAAAAAAAAEEBkPuG7BlXHtpbV59FrpSrclNA2iuPeoD3Kssg1cRyC8JBi1aJJBrV44hWtd8KaKnozM_wpohM69EuPLdNQc7v96UBAgMmIAEhWCBVEWSlJerLbRupcvBaXA5Cqpp1Ba46HZTH-dqgmeMCYSJYIIlzYLPXaVavxbpZ4G6ZJWJ6hwW_NgiKAHpSNL8Bwf_d"
	cborByte = make([]byte, base64Url.DecodedLen(len(attestationObj)))
	cborByte, err = base64Url.DecodeString(attestationObj)

	err = codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&m2)
	if err != nil {
		log.Fatal().Err(err).Msg("failed decoding cbor")
	}

	fmt.Println(fmt.Sprintf("fmt: %v", m2["fmt"]))
	fmt.Println(fmt.Sprintf("authData: %v", hex.EncodeToString(m2["authData"].([]byte))))
	// rpIdHash
	sha := sha256.New()
	sha.Write([]byte(rp))
	//rpIdHash := sha.Sum(nil)

	// Attestation Verification Procedure
	// f(attStmt, authenticatorData, clientDataHash)
	// Android SafetyNet Attestation Example ClientDataJSON: eyJjaGFsbGVuZ2UiOiJEa1hCdWRCa2wzTzBlTUV5SGZBTVgxT2tRbHV4c2hjaW9WU3dITVJMUlhtd044SXJldHg3cWJ0MWx3Y0p4d0FxWUU0SUxTZjVwd3lHMEhXSWtEekVMUT09Iiwib3JpZ2luIjoid2ViYXV0aG4ub3JnIiwiaGFzaEFsZyI6IlNIQS0yNTYifQ
	// Authenticator Data: AttestationObject.AuthData: m2["authData"]
	if val, ok := m2["attStmt"]; ok {
		androidSafetyNetAttestationStmt := val.(map[interface{}]interface{})

		if res, ok := androidSafetyNetAttestationStmt["response"]; ok {
			encodedRawJWS := string(res.([]byte))
			fmt.Println("JWS: " + encodedRawJWS)
			token, err := jwt.ParseSigned(encodedRawJWS)
			if err != nil {
				log.Fatal().Err(err).Msg("failed parsing JWS")
			}

			// Verify that the attestation certificate is issued to the hostname "attest.android.com"
			rootCerts := x509.NewCertPool()
			if ok := rootCerts.AppendCertsFromPEM([]byte(rootPEM));!ok {
				panic("failed to parse root certificate")
			}

			opts := x509.VerifyOptions{
				Roots: rootCerts,
				DNSName: "attest.android.com",
			}

			// Let attestationCert be the attestation certificate.
			// go-jose internally verify that attestationCert is issued to the hostname "attest.android.com"
			attestationCert, err := token.Headers[0].Certificates(opts)
			if err != nil {
				log.Fatal().Err(err).Msg("failed verifying JWS")
			}

			response := &AndroidSafetyNetAttestationResponse{}
			if err := token.Claims(attestationCert[0][0].PublicKey, response); err != nil {
				log.Fatal().Err(err).Msg("failed extracting payload")
			}

			// TODO Verify that response is a valid SafetyNet response of version ver

			// Verify that the nonce in the response is identical to the Base64url encoding of
			// the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
			sha := sha256.New()
			sha.Write(clientDataInBytes)
			clientDataHash := sha.Sum(nil)
			authData := m2["authData"].([]byte)
			buf := append(clientDataHash, authData...)
			sha = sha256.New()
			sha.Write(buf)

			if response.Nonce != base64.URLEncoding.EncodeToString(sha.Sum(nil)) {
				log.Fatal().Err(errors.New("")).Msg("failed extracting payload")
			}

			// Verify that the ctsProfileMatch attribute in the payload of response is true
			if !response.CtsProfileMatch {
				log.Fatal().Err(errors.New("")).Msg("CTS Profile is not true")
			}


			// If successful, return attestation type Basic with the attestation trust path set to the above attestation certificate
		}
	}

	fmt.Println("================ Android SafetyNet attestation in struct ===============")
	//ao := AttestationObject{AttStmt: AndroidSafetyNetAttestationStmt{}}
	//ao := AttestationObject{}
	//if err := codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&ao); err != nil {
	//	log.Fatal().Err(err).Msg("failed decoding cbor")
	//}
	//fmt.Println("fmt: " + ao.Fmt)
	//fmt.Println("authData: ", hex.EncodeToString(ao.AuthData))
	//fmt.Println(fmt.Sprintf("Android SafetyNet Version: %v", ao.AttStmt.(AndroidSafetyNetAttestationStmt).Ver))
	//fmt.Println(fmt.Sprintf("Android SafetyNet Response: %s", ao.AttStmt.(AndroidSafetyNetAttestationStmt).Response))
	//
	//fmt.Println("rpIdHash in AuthData" + hex.EncodeToString(ao.AuthData[0:32]))
	//flags := ao.AuthData[32]
	//fmt.Printf("%b\n", flags)
	//for i := uint(0); i < 8; i++ {
	//	fmt.Println(flags & (1 << i) >> i)
	//}
	//fmt.Println("User Presence: " + fmt.Sprintf("%b", flags&(1<<0)>>0))
	//// Bit1, 3-6
	////fmt.Println("Reserved for future: " + fmt.Sprintf("%b",flags & (1 << 1) >> 1))
	//fmt.Println("User Verification: " + fmt.Sprintf("%b", flags&(1<<2)>>2))
	//fmt.Println("Attested Credential Data: " + fmt.Sprintf("%b", flags&(1<<6)>>6))
	//fmt.Println("Extension data included: " + fmt.Sprintf("%b", flags&(1<<7)>>7))
	//fmt.Println("signCount in AuthData" + hex.EncodeToString(ao.AuthData[33:37]))
	//attestedCredentialData := ao.AuthData[37:xxxx] Length depends on https://www.w3.org/TR/webauthn/#attested-credential-data
	//extentions := ao.AuthData[xxxx:yyyy] Length depends on https://www.w3.org/TR/webauthn/#extension-identifier

	// HandlerFunc is a method of multiplexer (ServerMux)
	// Handler implements ServeHTTP(ResponseWriter, *Request)
	http.HandleFunc("/hello", myServer)

	//an HTTP request multiplexer
	_ = &CustomServeMux{} //mux := &CustomServeMux{}

	// ServerMux also implements ServeHTTP(ResponseWriter, *Request)
	newMux := http.NewServeMux()
	newMux.HandleFunc("/randomFloat", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, rand.Float64())
	})
	newMux.HandleFunc("/randomInt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, rand.Intn(100))
	})

	// Gorilla Mux
	r := mux.NewRouter()

	// curl -XPOST "http://localhost:8000" -> 405 Method Not Allowed
	r.HandleFunc("/", QueryHandler).Methods(http.MethodGet)

	r.UseEncodedPath()

	// curl "http://localhost:8000/articles -> 200
	// curl "http://localhost:8000/articles/ -> 404
	//r.StrictSlash(false) // default
	//r.Path("/articles").HandlerFunc(ArticleHandler)

	// curl "http://localhost:8000/articles -> 200
	// curl "http://localhost:8000/articles/ -> 301 to articles
	//r.StrictSlash(true) // default
	//r.Path("/articles").HandlerFunc(ArticleHandler)

	// curl "http://localhost:8000/articles"  -> curl "http://localhost:8000/articles/{empty}/{empty}"
	r.PathPrefix("/articles").HandlerFunc(ArticleHandler)

	// curl http://localhost:8000/articles/books/123
	s := r.PathPrefix("/articles").Subrouter()
	s.HandleFunc("/{category}/{id:[0-9]+}", ArticleHandler).Name("articleRoute")
	// is pretty much -> r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).Name("articleRoute")

	// curl "http://localhost:8000?id=123&category=books"
	r.Queries("id", "category")
	r.PathPrefix("/articles/").HandlerFunc(ArticleHandler)

	//url, _ := s.Get("articleRoute").URL("category", "books", "id", "123")
	//fmt.Printf(url.String())

	r.Path("/register").Methods(http.MethodPost).HandlerFunc(RegisterHandler)

	srv := &http.Server{
		Handler: r, //newMux,
		Addr:    "127.0.0.1:" + string(config.Port),
	}

	log.Fatal().Err(srv.ListenAndServe())
}

// RegisterHandler
// FIDO: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#example-credential-creation-options
// ex: curl -XPOST "http://localhost:8000/register" -H "Content-Type: application/json" -d '{"userName": "value", "displayName": "ken5"}' -v
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var optionsRequest ServerPublicKeyCredentialCreationOptionsRequest
	var optionsResponse ServerPublicKeyCredentialCreationOptionsResponse
	var fidoError FidoError

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		// TODO do proper error handling
		fidoError.Status = "failed"
		fidoError.ErrorMessage = "failed reading body: " + err.Error()
		log.Error().Err(err).Msg("failed reading body")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&fidoError)
		return
	}

	// Decode Credential Creation Options Options Request Body
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&optionsRequest); err != nil {
		// TODO do proper error handling
		fidoError.Status = "failed"
		fidoError.ErrorMessage = "failed parsing body: " + err.Error()
		log.Error().Err(err).Msg("failed parsing body")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&fidoError)
		return
	}

	// Validate Credential Creation Options Options Request
	if err := optionsRequest.validate(); err != nil {
		// TODO do proper error handling
		fidoError.Status = "failed"
		fidoError.ErrorMessage = err.Error()
		log.Error().Err(err).Msg("Bad Parameter")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(&fidoError)
		return
	} else {
		sha := sha256.New()
		sha.Write([]byte(""))
		challenge = hex.EncodeToString(sha.Sum(nil))

		optionsResponse.Challenge = challenge
		optionsResponse.PublicKeyCredentialRpEntity = struct {
			Name string `json:"name"`
		}{rp}
		optionsResponse.ServerPublicKeyCredentialUserEntity = struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		}{uuid, optionsRequest.UserName, optionsRequest.DisplayName}
		optionsResponse.PublicKeyCredentialParameters = []PubKeyParam{{Type: "publick-key", Alg: -7}} //For Now, just use ES256
	}

	// Encode Response
	if err := json.NewEncoder(w).Encode(&optionsResponse); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Error().Err(err).Msg(fmt.Sprintf("failed encoding option response: %v", optionsResponse))
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func QueryHandler(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Got parameter id:%s!\n", queryParams["id"])
	fmt.Fprintf(w, "Got parameter category:%s!", queryParams["category"])
}

func ArticleHandler(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Category is: %v\n", vars["category"])
	fmt.Fprintf(w, "ID is: %v\n", vars["id"])
}

func myServer(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "hello world\n")
}

type CustomServeMux struct{}

func (c *CustomServeMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/" {
		giveRandom(w, r)
		return
	}
	http.NotFound(w, r)
	return
}

func giveRandom(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Your random number is: %f", rand.Float64())
}
