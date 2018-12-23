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
	attestationObj = "o2hhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQKglxHyfnRKAZVqiJdIqtqf4I9dx0oO6_zAO8TnDojvEZAq2DZkByI1fcoWVQEq_O3FLH5aOwzbrrxrJ65U5dYqlAQIDJiABIVggh5OJfYRDzVGIowKqU57AnoVjjdmmjGi9zlMkjAVV9DAiWCDr0iSi0viIKNPMTIdN28gWNmkcwOr6DQx66MPff3Odm2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDEyNjg1MDIzaHJlc3BvbnNlWRSnZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGYVdwRFEwRXpTMmRCZDBsQ1FXZEpTVmxyV1c4MVJqQm5PRFpyZDBSUldVcExiMXBKYUhaalRrRlJSVXhDVVVGM1ZrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaElha0ZqUW1kT1ZrSkJiMVJHVldSMllqSmtjMXBUUWxWamJsWjZaRU5DVkZwWVNqSmhWMDVzWTNwRmJFMURUVWRCTVZWRlFYaE5ZMUl5T1haYU1uaHNTVVZzZFdSSFZubGliVll3U1VWR01XUkhhSFpqYld3d1pWTkNTRTE2UVdWR2R6QjRUbnBGZVUxRVVYaE5la1UwVGtST1lVWjNNSGhQUkVWNVRVUk5kMDFFUVhkTlJFSmhUVWQzZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWsxM1JWRlpSRlpSVVVsRVFYQkVXVmQ0Y0ZwdE9YbGliV3hvVFZKWmQwWkJXVVJXVVZGSVJFRXhUbUl6Vm5Wa1IwWndZbWxDVjJGWFZqTk5VazEzUlZGWlJGWlJVVXRFUVhCSVlqSTVibUpIVldkVFZ6VnFUVkp6ZDBkUldVUldVVkZFUkVKS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVU5WYWpoM1dXOVFhWGhMWW1KV09ITm5XV2QyVFZSbVdDdGtTWE5HVkU5clowdFBiR2hVTUdrd1ltTkVSbHBMTW5KUGVFcGFNblZUVEZOV2FGbDJhWEJhVGtVelNFcFJXWFYxV1hkR2FtbDVLM2xyWm1GMFFVZFRhbEo2UmpGaU16RjFORE12TjI5SE5XcE5hRE5UTXpkaGJIZHFWV0k0UTFkcFZIaHZhWEJXVDFsM1MwdDZkVlY1YTNGRlEzUnFiR2hLTkVGclYyRkVVeXRhZUV0RmNVOWhaVGwwYmtOblpVaHNiRnBGTDA5U1oyVk5ZWGd5V0U1RGIwZzJjM0pVUlZKamEzTnFlbHBhY2tGWGVFdHpaR1oyVm5KWVRucERVamxFZUZaQlUzVkpOa3g2ZDJnNFJGTnNNa1ZQYjJ0aWMyRnVXaXNyTDBweFRXVkJRa1ptVUhkcWVYZHlZakJ3Y2tWVmVUQndZV1ZXYzNWa0t6QndaV1Y0U3k4MUswVTJhM0JaUjBzMFdrc3libXR2Vmt4MVowVTFkR0ZJY2tGcU9ETlJLMUJQWW1KMlQzcFhZMFpyY0c1V1MzbHFielpMVVVGdFdEWlhTa0ZuVFVKQlFVZHFaMmRHUjAxSlNVSlJha0ZVUW1kT1ZraFRWVVZFUkVGTFFtZG5ja0puUlVaQ1VXTkVRVlJCWkVKblRsWklVa1ZGUm1wQlZXZG9TbWhrU0ZKc1l6TlJkVmxYTld0amJUbHdXa00xYW1JeU1IZGhRVmxKUzNkWlFrSlJWVWhCVVVWRldFUkNZVTFETUVkRFEzTkhRVkZWUmtKNlFVTm9hVVp2WkVoU2QwOXBPSFpqUjNSd1RHMWtkbUl5WTNaYU0wNTVUV2s1U0ZaR1RraFRWVVpJVFhrMWFtTnVVWGRMVVZsSlMzZFpRa0pSVlVoTlFVZEhTRmRvTUdSSVFUWk1lVGwyV1ROT2QweHVRbkpoVXpWdVlqSTVia3d3WkZWVk1HUktVVlZqZWsxQ01FZEJNVlZrUkdkUlYwSkNVVWM0U1hKUmRFWlNOa05WVTJ0cGEySXpZV2x0YzIweU5tTkNWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdTR1pEZFVaRFlWb3pXakp6VXpORGFIUkRSRzlJTm0xbWNuQk1UVU5GUjBFeFZXUkpRVkZoVFVKbmQwUkJXVXRMZDFsQ1FrRklWMlZSU1VaQmVrRkpRbWRhYm1kUmQwSkJaMGwzVFZGWlJGWlNNR1pDUTI5M1MwUkJiVzlEVTJkSmIxbG5ZVWhTTUdORWIzWk1NazU1WWtNMWQyRXlhM1ZhTWpsMlduazVTRlpHVGtoVFZVWklUWGsxYW1OdGQzZEVVVmxLUzI5YVNXaDJZMDVCVVVWTVFsRkJSR2RuUlVKQlJpOVNlazV1UXpWRWVrSlZRblJ1YURKdWRFcE1WMFZSYURsNlJXVkdXbVpRVERsUmIydHliRUZ2V0dkcVYyZE9PSEJUVWxVeGJGWkhTWEIwZWsxNFIyaDVNeTlQVWxKYVZHRTJSREpFZVRob2RrTkVja1pKTXl0c1Exa3dNVTFNTlZFMldFNUZOVkp6TW1ReFVtbGFjRTF6ZWtRMFMxRmFUa2N6YUZvd1FrWk9VUzlqYW5KRGJVeENUMGRMYTBWVk1XUnRRVmh6UmtwWVNtbFBjakpEVGxSQ1QxUjFPVVZpVEZkb1VXWmtRMFl4WW5kNmVYVXJWelppVVZOMk9GRkVialZQWkUxVEwxQnhSVEZrUldkbGRDODJSVWxTUWpjMk1VdG1XbEVyTDBSRk5reHdNMVJ5V2xSd1QwWkVSR2RZYUN0TVowZFBjM2RvUld4cU9XTXpkbHBJUjBwdWFHcHdkRGh5YTJKcGNpOHlkVXhIWm5oc1ZsbzBTekY0TlVSU1RqQlFWVXhrT1hsUVUyMXFaeXRoYWpFcmRFaDNTVEZ0VVcxYVZsazNjWFpQTlVSbmFFOTRhRXBOUjJ4Nk5teE1hVnB0ZW05blBTSXNJazFKU1VWWVJFTkRRVEJUWjBGM1NVSkJaMGxPUVdWUGNFMUNlamhqWjFrMFVEVndWRWhVUVU1Q1oydHhhR3RwUnpsM01FSkJVWE5HUVVSQ1RVMVRRWGRJWjFsRVZsRlJURVY0WkVoaVJ6bHBXVmQ0VkdGWFpIVkpSa3AyWWpOUloxRXdSV2RNVTBKVFRXcEZWRTFDUlVkQk1WVkZRMmhOUzFJeWVIWlpiVVp6VlRKc2JtSnFSVlJOUWtWSFFURlZSVUY0VFV0U01uaDJXVzFHYzFVeWJHNWlha0ZsUm5jd2VFNTZRVEpOVkZWM1RVUkJkMDVFU21GR2R6QjVUVlJGZVUxVVZYZE5SRUYzVGtSS1lVMUdVWGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVkkwZDBoQldVUldVVkZMUlhoV1NHSXlPVzVpUjFWblZraEtNV016VVdkVk1sWjVaRzFzYWxwWVRYaEtWRUZxUW1kT1ZrSkJUVlJJUldSMllqSmtjMXBUUWtwaWJsSnNZMjAxYkdSRFFrSmtXRkp2WWpOS2NHUklhMmRTZWsxM1oyZEZhVTFCTUVkRFUzRkhVMGxpTTBSUlJVSkJVVlZCUVRSSlFrUjNRWGRuWjBWTFFXOUpRa0ZSUkV0VmEzWnhTSFl2VDBwSGRXOHlia2xaWVU1V1YxaFJOVWxYYVRBeFExaGFZWG8yVkVsSVRFZHdMMnhQU2lzMk1EQXZOR2hpYmpkMmJqWkJRVUl6UkZaNlpGRlBkSE0zUnpWd1NEQnlTbTV1VDBaVlFVczNNVWMwYm5wTFRXWklRMGRWYTNOWEwyMXZibUVyV1RKbGJVcFJNazRyWVdsamQwcExaWFJRUzFKVFNXZEJkVkJQUWpaQllXaG9PRWhpTWxoUE0yZzVVbFZyTWxRd1NFNXZkVUl5Vm5wNGIwMVliR3Q1VnpkWVZWSTFiWGMyU210TVNHNUJOVEpZUkZadlVsUlhhMDUwZVRWdlEwbE9USFpIYlc1U2Mwb3hlbTkxUVhGWlIxWlJUV012TjNONUt5OUZXV2hCVEhKV1NrVkJPRXRpZEhsWUszSTRjMjUzVlRWRE1XaFZjbmRoVnpaTlYwOUJVbUU0Y1VKd1RsRmpWMVJyWVVsbGIxbDJlUzl6UjBsS1JXMXFVakIyUmtWM1NHUndNV05UWVZkSmNqWXZOR2MzTW00M1QzRllkMlpwYm5VM1dsbFhPVGRGWm05UFUxRktaVUY2UVdkTlFrRkJSMnBuWjBWNlRVbEpRa3g2UVU5Q1owNVdTRkU0UWtGbU9FVkNRVTFEUVZsWmQwaFJXVVJXVWpCc1FrSlpkMFpCV1VsTGQxbENRbEZWU0VGM1JVZERRM05IUVZGVlJrSjNUVU5OUWtsSFFURlZaRVYzUlVJdmQxRkpUVUZaUWtGbU9FTkJVVUYzU0ZGWlJGWlNNRTlDUWxsRlJraG1RM1ZHUTJGYU0xb3ljMU16UTJoMFEwUnZTRFp0Wm5Kd1RFMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1NuWnBRakZrYmtoQ04wRmhaMkpsVjJKVFlVeGtMMk5IV1ZsMVRVUlZSME5EYzBkQlVWVkdRbmRGUWtKRGEzZEtla0ZzUW1kbmNrSm5SVVpDVVdOM1FWbFpXbUZJVWpCalJHOTJUREk1YW1NelFYVmpSM1J3VEcxa2RtSXlZM1phTTA1NVRXcEJlVUpuVGxaSVVqaEZTM3BCY0UxRFpXZEtZVUZxYUdsR2IyUklVbmRQYVRoMldUTktjMHh1UW5KaFV6VnVZakk1Ymt3eVpIcGpha2wyV2pOT2VVMXBOV3BqYlhkM1VIZFpSRlpTTUdkQ1JHZDNUbXBCTUVKbldtNW5VWGRDUVdkSmQwdHFRVzlDWjJkeVFtZEZSa0pSWTBOQlVsbGpZVWhTTUdOSVRUWk1lVGwzWVRKcmRWb3lPWFphZVRsNVdsaENkbU15YkRCaU0wbzFUSHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUVU5RFFWRkZRVWhNWlVwc2RWSlVOMkoyY3pJMlozbEJXamh6YnpneGRISlZTVk5rTjA4ME5YTnJSRlZ0UVdkbE1XTnVlR2hITVZBeVkwNXRVM2hpVjNOdmFVTjBNbVYxZURsTVUwUXJVRUZxTWt4SldWSkdTRmN6TVM4MmVHOXBZekZyTkhSaVYxaHJSRU5xYVhJek4zaFVWRTV4VWtGTlVGVjVSbEpYVTJSMmRDdHViRkJ4ZDI1aU9FOWhNa2t2YldGVFNuVnJZM2hFYWs1VFpuQkVhQzlDWkRGc1drNW5aR1F2T0dOTVpITkZNeXQzZVhCMVprbzVkVmhQTVdsUmNHNW9PWHBpZFVaSmQzTkpUMDVIYkRGd00wRTRRMmQ0YTNGSkwxVkJhV2d6U21GSFQzRmpjR05rWVVOSmVtdENZVkk1ZFZsUk1WZzBhekpXWnpWQlVGSk1iM1Y2Vm5rM1lUaEpWbXMyZDNWNU5uQnRLMVEzU0ZRMFRGazRhV0pUTlVaRldteG1RVVpNVTFjNFRuZHpWbm81VTBKTE1sWnhiakZPTUZCSlRXNDFlRUUyVGxwV1l6ZHZPRE0xUkV4QlJuTm9SVmRtUXpkVVNXVXpaejA5SWwxOS5leUp1YjI1alpTSTZJbXhYYTBscWVEZFBOSGxOY0ZaQlRtUjJVa1JZZVhWUFVrMUdiMjVWWWxaYWRUUXZXSGszU1hCMlpGSkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVkZMWjJ4NFNIbG1ibEpMUVZwV2NXbEtaRWx4ZEhGbU5FazVaSGd3YjA4MkwzcEJUemhVYmtSdmFuWkZXa0Z4TWtSYWEwSjVTVEZtWTI5WFZsRkZjUzlQTTBaTVNEVmhUM2Q2WW5KeWVISktOalZWTldSWmNXeEJVVWxFU21sQlFrbFdaMmRvTlU5S1psbFNSSHBXUjBsdmQwdHhWVFUzUVc1dlZtcHFaRzF0YWtkcE9YcHNUV3RxUVZaV09VUkJhVmREUkhJd2FWTnBNSFpwU1V0T1VFMVVTV1JPTWpoblYwNXRhMk4zVDNJMlJGRjROalpOVUdabU0wOWtiU3QxTm1WS2NVeENiREZJTWxNeWRISkJRa2hNYVc1cmJuTjVWazFRYlM5Q1RsVldXakpLUm14eU9EQWlMQ0owYVcxbGMzUmhiWEJOY3lJNk1UVXlPRGt4TVRZek5ETTROU3dpWVhCclVHRmphMkZuWlU1aGJXVWlPaUpqYjIwdVoyOXZaMnhsTG1GdVpISnZhV1F1WjIxeklpd2lZWEJyUkdsblpYTjBVMmhoTWpVMklqb2lTazlETTFWcmMyeHpkVlo2TVRObFQzQnVSa2s1UW5CTWIzRkNaemxyTVVZMlQyWmhVSFJDTDBkcVRUMGlMQ0pqZEhOUWNtOW1hV3hsVFdGMFkyZ2lPbVpoYkhObExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUpIV0ZkNU9GaEdNM1pKYld3ekwwMW1ibTFUYlhsMVMwSndWRE5DTUdSWFlraFNVaTgwWTJkeEsyZEJQU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2Wm1Gc2MyVXNJbUZrZG1salpTSTZJbEpGVTFSUFVrVmZWRTlmUmtGRFZFOVNXVjlTVDAwc1RFOURTMTlDVDA5VVRFOUJSRVZTSW4wLmlDRjZEMm9zOERZdURWT250M3pESkIybVNYblpqdFdKdGxfanpTRHg1TXJSQzlBMmZtRkJaNno1a3BRWjJNaVE3b290ajlXa0hNZ3hxSWhyWDNkbGgyUE9IQXdrSVMzNHlTakxWTnNTUHByRTg0ZVpncVNGTE1FWVQwR1IyZVZMSEFNUE44bjVSOEs2YnVET0dGM25TaTZHS3pHNTdabGw4Q1NvYjJ5aUFTOXI3c3BkQTZIMFRESC1OR3pTZGJNSUlkOGZaRDFkekZLTlFyNzdiNmxiSUFGZ1FiUlpCcm5wLWUtSDRpSDZkMjFvTjJOQVlSblI1WVVSYWNQNmtHR2oyY0Z4c3dFMjkwOHd4djloaVlOS05vamVldThYYzRJdDdQYmhsQXVPN3l3aFFGQTgxaVBDQ0ZtMTFCOGNmVVhiV0E4bF8ydHROUEJFTUdNNi1aNlZ5UQ"
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
			//encodedRawJWS := string(res.([]byte))
			// TODO ↓のサンプルは古く、Android Attestationについてくる証明書の有効期限がすでに切れていたため、YuryのＢｌｏｇにあったJWTをコピっている
			// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#examples
			// https://medium.com/@herrjemand/verifying-fido2-safetynet-attestation-bd261ce1978d
			fmt.Println("Old: " + string(res.([]byte)))
			encodedRawJWS := "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGa2pDQ0JIcWdBd0lCQWdJUVJYcm9OMFpPZFJrQkFBQUFBQVB1bnpBTkJna3Foa2lHOXcwQkFRc0ZBREJDTVFzd0NRWURWUVFHRXdKVlV6RWVNQndHQTFVRUNoTVZSMjl2WjJ4bElGUnlkWE4wSUZObGNuWnBZMlZ6TVJNd0VRWURWUVFERXdwSFZGTWdRMEVnTVU4eE1CNFhEVEU0TVRBeE1EQTNNVGswTlZvWERURTVNVEF3T1RBM01UazBOVm93YkRFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ1RDa05oYkdsbWIzSnVhV0V4RmpBVUJnTlZCQWNURFUxdmRXNTBZV2x1SUZacFpYY3hFekFSQmdOVkJBb1RDa2R2YjJkc1pTQk1URU14R3pBWkJnTlZCQU1URW1GMGRHVnpkQzVoYm1SeWIybGtMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTmpYa3owZUsxU0U0bSsvRzV3T28rWEdTRUNycWRuODhzQ3BSN2ZzMTRmSzBSaDNaQ1laTEZIcUJrNkFtWlZ3Mks5RkcwTzlyUlBlUURJVlJ5RTMwUXVuUzl1Z0hDNGVnOW92dk9tK1FkWjJwOTNYaHp1blFFaFVXWEN4QURJRUdKSzNTMmFBZnplOTlQTFMyOWhMY1F1WVhIRGFDN09acU5ub3NpT0dpZnM4djFqaTZIL3hobHRDWmUybEorN0d1dHpleEtweHZwRS90WlNmYlk5MDVxU2xCaDlmcGowMTVjam5RRmtVc0FVd21LVkFVdWVVejR0S2NGSzRwZXZOTGF4RUFsK09raWxNdElZRGFjRDVuZWw0eEppeXM0MTNoYWdxVzBXaGg1RlAzOWhHazlFL0J3UVRqYXpTeEdkdlgwbTZ4RlloaC8yVk15WmpUNEt6UEpFQ0F3RUFBYU9DQWxnd2dnSlVNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBVEFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCUXFCUXdHV29KQmExb1RLcXVwbzRXNnhUNmoyREFmQmdOVkhTTUVHREFXZ0JTWTBmaHVFT3ZQbSt4Z254aVFHNkRyZlFuOUt6QmtCZ2dyQmdFRkJRY0JBUVJZTUZZd0p3WUlLd1lCQlFVSE1BR0dHMmgwZEhBNkx5OXZZM053TG5CcmFTNW5iMjluTDJkMGN6RnZNVEFyQmdnckJnRUZCUWN3QW9ZZmFIUjBjRG92TDNCcmFTNW5iMjluTDJkemNqSXZSMVJUTVU4eExtTnlkREFkQmdOVkhSRUVGakFVZ2hKaGRIUmxjM1F1WVc1a2NtOXBaQzVqYjIwd0lRWURWUjBnQkJvd0dEQUlCZ1puZ1F3QkFnSXdEQVlLS3dZQkJBSFdlUUlGQXpBdkJnTlZIUjhFS0RBbU1DU2dJcUFnaGg1b2RIUndPaTh2WTNKc0xuQnJhUzVuYjI5bkwwZFVVekZQTVM1amNtd3dnZ0VFQmdvckJnRUVBZFo1QWdRQ0JJSDFCSUh5QVBBQWR3Q2t1UW1RdEJoWUZJZTdFNkxNWjNBS1BEV1lCUGtiMzdqamQ4ME95QTNjRUFBQUFXWmREM1BMQUFBRUF3QklNRVlDSVFDU1pDV2VMSnZzaVZXNkNnK2dqLzl3WVRKUnp1NEhpcWU0ZVk0Yy9teXpqZ0loQUxTYmkvVGh6Y3pxdGlqM2RrM3ZiTGNJVzNMbDJCMG83NUdRZGhNaWdiQmdBSFVBVmhRR21pL1h3dXpUOWVHOVJMSSt4MFoydWJ5WkVWekE3NVNZVmRhSjBOMEFBQUZtWFE5ejVBQUFCQU1BUmpCRUFpQmNDd0E5ajdOVEdYUDI3OHo0aHIvdUNIaUFGTHlvQ3EySzAreUxSd0pVYmdJZ2Y4Z0hqdnB3Mm1CMUVTanEyT2YzQTBBRUF3Q2tuQ2FFS0ZVeVo3Zi9RdEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUk5blRmUktJV2d0bFdsM3dCTDU1RVRWNmthenNwaFcxeUFjNUR1bTZYTzQxa1p6d0o2MXdKbWRSUlQvVXNDSXkxS0V0MmMwRWpnbG5KQ0YyZWF3Y0VXbExRWTJYUEx5RmprV1FOYlNoQjFpNFcyTlJHelBodDNtMWI0OWhic3R1WE02dFg1Q3lFSG5UaDhCb200L1dsRmloemhnbjgxRGxkb2d6L0syVXdNNlM2Q0IvU0V4a2lWZnYremJKMHJqdmc5NEFsZGpVZlV3a0k5Vk5NakVQNWU4eWRCM29MbDZnbHBDZUY1ZGdmU1g0VTl4MzVvai9JSWQzVUUvZFBwYi9xZ0d2c2tmZGV6dG1VdGUvS1Ntcml3Y2dVV1dlWGZUYkkzenNpa3daYmtwbVJZS21qUG1odjRybGl6R0NHdDhQbjhwcThNMktEZi9QM2tWb3QzZTE4UT0iLCJNSUlFU2pDQ0F6S2dBd0lCQWdJTkFlTzBtcUdOaXFtQkpXbFF1REFOQmdrcWhraUc5dzBCQVFzRkFEQk1NU0F3SGdZRFZRUUxFeGRIYkc5aVlXeFRhV2R1SUZKdmIzUWdRMEVnTFNCU01qRVRNQkVHQTFVRUNoTUtSMnh2WW1Gc1UybG5iakVUTUJFR0ExVUVBeE1LUjJ4dlltRnNVMmxuYmpBZUZ3MHhOekEyTVRVd01EQXdOREphRncweU1URXlNVFV3TURBd05ESmFNRUl4Q3pBSkJnTlZCQVlUQWxWVE1SNHdIQVlEVlFRS0V4VkhiMjluYkdVZ1ZISjFjM1FnVTJWeWRtbGpaWE14RXpBUkJnTlZCQU1UQ2tkVVV5QkRRU0F4VHpFd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURRR005RjFJdk4wNXprUU85K3ROMXBJUnZKenp5T1RIVzVEekVaaEQyZVBDbnZVQTBRazI4RmdJQ2ZLcUM5RWtzQzRUMmZXQllrL2pDZkMzUjNWWk1kUy9kTjRaS0NFUFpSckF6RHNpS1VEelJybUJCSjV3dWRnem5kSU1ZY0xlL1JHR0ZsNXlPRElLZ2pFdi9TSkgvVUwrZEVhbHROMTFCbXNLK2VRbU1GKytBY3hHTmhyNTlxTS85aWw3MUkyZE44RkdmY2Rkd3VhZWo0YlhocDBMY1FCYmp4TWNJN0pQMGFNM1Q0SStEc2F4bUtGc2JqemFUTkM5dXpwRmxnT0lnN3JSMjV4b3luVXh2OHZObWtxN3pkUEdIWGt4V1k3b0c5aitKa1J5QkFCazdYckpmb3VjQlpFcUZKSlNQazdYQTBMS1cwWTN6NW96MkQwYzF0Skt3SEFnTUJBQUdqZ2dFek1JSUJMekFPQmdOVkhROEJBZjhFQkFNQ0FZWXdIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0hRWURWUjBPQkJZRUZKalIrRzRRNjgrYjdHQ2ZHSkFib090OUNmMHJNQjhHQTFVZEl3UVlNQmFBRkp2aUIxZG5IQjdBYWdiZVdiU2FMZC9jR1lZdU1EVUdDQ3NHQVFVRkJ3RUJCQ2t3SnpBbEJnZ3JCZ0VGQlFjd0FZWVphSFIwY0RvdkwyOWpjM0F1Y0d0cExtZHZiMmN2WjNOeU1qQXlCZ05WSFI4RUt6QXBNQ2VnSmFBamhpRm9kSFJ3T2k4dlkzSnNMbkJyYVM1bmIyOW5MMmR6Y2pJdlozTnlNaTVqY213d1B3WURWUjBnQkRnd05qQTBCZ1puZ1F3QkFnSXdLakFvQmdnckJnRUZCUWNDQVJZY2FIUjBjSE02THk5d2Eya3VaMjl2Wnk5eVpYQnZjMmwwYjNKNUx6QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFHb0ErTm5uNzh5NnBSamQ5WGxRV05hN0hUZ2laL3IzUk5Ha21VbVlIUFFxNlNjdGk5UEVhanZ3UlQyaVdUSFFyMDJmZXNxT3FCWTJFVFV3Z1pRK2xsdG9ORnZoc085dHZCQ09JYXpwc3dXQzlhSjl4anU0dFdEUUg4TlZVNllaWi9YdGVEU0dVOVl6SnFQalk4cTNNRHhyem1xZXBCQ2Y1bzhtdy93SjRhMkc2eHpVcjZGYjZUOE1jRE8yMlBMUkw2dTNNNFR6czNBMk0xajZieWtKWWk4d1dJUmRBdktMV1p1L2F4QlZielltcW13a201ekxTRFc1bklBSmJFTENRQ1p3TUg1NnQyRHZxb2Z4czZCQmNDRklaVVNweHU2eDZ0ZDBWN1N2SkNDb3NpclNtSWF0ai85ZFNTVkRRaWJldDhxLzdVSzR2NFpVTjgwYXRuWnoxeWc9PSJdfQ.eyJub25jZSI6IlhQQjdWVGRSWGJEM01mMENvTFF5ZVJQclA5ZjIzYW9mVHBtVWd6cmlrbzA9IiwidGltZXN0YW1wTXMiOjE1NDA2NTE2ODQwOTMsImFwa1BhY2thZ2VOYW1lIjoiY29tLmdvb2dsZS5hbmRyb2lkLmdtcyIsImFwa0RpZ2VzdFNoYTI1NiI6ImVRYyt2elVjZHgwRlZOTHZYSHVHcEQwK1I4MDdzVUV2cCtKZWxlWVpzaUE9IiwiY3RzUHJvZmlsZU1hdGNoIjp0cnVlLCJhcGtDZXJ0aWZpY2F0ZURpZ2VzdFNoYTI1NiI6WyI4UDFzVzBFUEpjc2x3N1V6UnNpWEw2NHcrTzUwRWQrUkJJQ3RheTFnMjRNPSJdLCJiYXNpY0ludGVncml0eSI6dHJ1ZX0.emYayEmcZR5nGyQ0yayZIwSa8zDC4zCWdzvh9seR3hXYBcmV9lL6PmWp-H58FMnuEahH2HgMAyHo0xPjB0xr1QzFzsbNmEsC-_LotaviM3VIuWahejkx_Rob-0q3vhCqCYyraMiTcFkzN-bXgauBO0Md9eAGFBR5P0pLnui8_6hpo6wRNA74lGKAs0kOi4A9jUs7Na-A4OaeyYs8Q3q425S7fu6Pzadk4rkZclfEvPIjMqFFCCO-_llXvHTap4S09_W6tFpR_cw9JXL7g5dUcca5iWoDZxXztsKRz3p1cA1M2gkZsmMWCYD6Kv4BIsHtiitwhL2SNC8QZiYc1Wxj3A"
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
	ao := AttestationObject{AttStmt: AndroidSafetyNetAttestationStmt{}}
	//ao := AttestationObject{}
	if err := codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&ao); err != nil {
		log.Fatal().Err(err).Msg("failed decoding cbor")
	}
	fmt.Println("fmt: " + ao.Fmt)
	fmt.Println("authData: ", hex.EncodeToString(ao.AuthData))
	fmt.Println(fmt.Sprintf("Android SafetyNet Version: %v", ao.AttStmt.(AndroidSafetyNetAttestationStmt).Ver))
	fmt.Println(fmt.Sprintf("Android SafetyNet Response: %s", ao.AttStmt.(AndroidSafetyNetAttestationStmt).Response))

	fmt.Println("rpIdHash in AuthData" + hex.EncodeToString(ao.AuthData[0:32]))
	flags := ao.AuthData[32]
	fmt.Printf("%b\n", flags)
	for i := uint(0); i < 8; i++ {
		fmt.Println(flags & (1 << i) >> i)
	}
	fmt.Println("User Presence: " + fmt.Sprintf("%b", flags&(1<<0)>>0))
	// Bit1, 3-6
	//fmt.Println("Reserved for future: " + fmt.Sprintf("%b",flags & (1 << 1) >> 1))
	fmt.Println("User Verification: " + fmt.Sprintf("%b", flags&(1<<2)>>2))
	fmt.Println("Attested Credential Data: " + fmt.Sprintf("%b", flags&(1<<6)>>6))
	fmt.Println("Extension data included: " + fmt.Sprintf("%b", flags&(1<<7)>>7))
	fmt.Println("signCount in AuthData" + hex.EncodeToString(ao.AuthData[33:37]))
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
