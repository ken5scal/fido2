package main

import (
	"bytes"
	"crypto/sha256"
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
	"encoding/base64"
)

var rp = "secure-brigate"
var uuid = "S3932ee31vKEC0JtJMIQ"
var userName = "kengoscal@gmail.com"
var displayName = "ken5scal"
var challenge string
var config Config

type Config struct {
	Port uint
	Origin string
	Debug bool
}

type AttestationObject struct {
	fmt string
	attStmt AttestationStatement
	authData string
}

type AttestationStatement struct {
	sig string
	x5c []string
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

type A struct {
	I int
	S string
}
type B float64
type C struct {
	Fun bool
	Amt int
}

var v1 A
var v2 *A = &v1
var v3 int = 9
var v4 bool = false
var v5 interface{} = v3
var v6 interface{} = nil
var v7 B
var v8 *B = &v7

func main() {
	// Testing JSON with Go/codec
	var m = map[string]*A{"1": &A{I: 1, S: "one"}, "2": &A{I: 2, S: "two"}}
	fmt.Printf("before: %v\n", m)
	var b = []byte(`{"1": {"I":111}, "3": {"I": 333} }`)
	if err := codec.NewDecoderBytes(b, new(codec.JsonHandle)).Decode(&m); err != nil {
		fmt.Println(err)
	}
	fmt.Printf(" after: %v\n", m)
	for k, v := range m {
		fmt.Printf("\t%v: %v\n", k, v)
	}

	ex := `{"Fun": true, "Amt": -2}`
	b = []byte(ex)
	var c C
	if err := codec.NewDecoderBytes(b, new(codec.JsonHandle)).Decode(&c); err != nil {
		fmt.Println(err)
	}
	fmt.Printf(" after: %v\n", c)
	fmt.Println(c.Amt)
	fmt.Println(c.Fun)

	// Testing CBOR with Go/codec
	//attestationObj := "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
	//attestationObjInBytes, err := base64.StdEncoding.DecodeString(attestationObj)
	fmt.Println(fmt.Sprintf("This is byte: %v", b))
	fmt.Println("Dumping Fun from byte: %s", hex.Dump(b))
	by, _ := hex.DecodeString("bf6346756ef563416d7421ff")
	fmt.Println("Duming Fun from hex: %s", hex.Dump(by))
	// androidSafetyNetAttestationObj := "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgRvfOaUcMVmHqrKzXSH2Inb4PIshESObwuPrtTS_W3RMCICF_qfvwZhDRF8bqiNGYty2iXcOxY8Tgi7TgQJHZqi4wY3g1Y4FZAlMwggJPMIIBN6ADAgECAgQ8aClNMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAxMS8wLQYDVQQDDCZZdWJpY28gVTJGIEVFIFNlcmlhbCAyMzkyNTczNDgxMTExNzkwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL3fZ5Pbd5TDUDFx7SxNRUrZc2Z1Gki6pdn5tWo6IIF5a07fK817knoUkxD7xGhHb_xXkql9ti-gKGvGoyACDmOjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMA0GCSqGSIb3DQEBCwUAA4IBAQCqwA1RCX7sFaSGs3m8xINA-GfTly7Oamf7pHDjYMZEWfCtOELT_wgeceqJU5cbI_klwK0AwkcxGFIG8LOpGSn7kbdmtT_hM1Iqg1i40SC0q_t_6O8ke2T_xqYhSsHZvnM2_eDzqBg_k0tSGHX14_eJgK-XClseBCo4dtdLqL7v6S3S43PMZEHIlK182aT0fa09pP6vR5GYR1PjWgic5Mvj08g26tCip86lYVrX5EgQhsN3s2ZE0vuZa7zimyGtuJX3k4LuxUk-TsEzwhZ_B3H1mTFzEg_yjVPogaiXQMEyzzw0aCy7z05dvcHggCIfh1KZgUHdFJbXDzqwPyxbwH-taGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAimCIoe8U_N9M1rTGeCqJ96TAu5uqSPa7YUzdh7qq-AdJlnBl8NwCpu2-sNj9UIVH5rAjX_RXlSGTGWKexKIZXKUBAgMmIAEhWCB7XpGVxTYo6jtkxB7sBR4Af_YM0GvInN5V7IvUIilN2yJYINphegJ6kNET_VIp0QOxssW8xxUFEgg5ic3HXmoGg4fS"
	// packedAttestationObj := "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIsK0Wr9tmud-waIYoQw20UWi7DL_gDx_PNG3PB57eHLAiEAtRyd-4JI2pCVX-dDz4mbHc_AkvC3d_4qnBBa3n2I_hVjeDVjg1kCRTCCAkEwggHooAMCAQICEBWfe8LNiRjxKGuTSPqfM-IwCgYIKoZIzj0EAwIwSTELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMRswGQYDVQQDDBJGZWl0aWFuIEZJRE8yIENBLTEwIBcNMTgwNDExMDAwMDAwWhgPMjAzMzA0MTAyMzU5NTlaMG8xCzAJBgNVBAYTAkNOMR0wGwYDVQQKDBRGZWl0aWFuIFRlY2hub2xvZ2llczEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEdMBsGA1UEAwwURlQgQmlvUGFzcyBGSURPMiBVU0IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASABnVcWfvJSbAVqNIKkliXvoMKsu_oLPiP7aCQlmPlSMcfEScFM7QkRnidTP7hAUOKlOmDPeIALC8qHddvTdtdo4GJMIGGMB0GA1UdDgQWBBR6VIJCgGLYiuevhJglxK-RqTSY8jAfBgNVHSMEGDAWgBRNO9jEZxUbuxPo84TYME-daRXAgzAMBgNVHRMBAf8EAjAAMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEEI4MkVENzNDOEZCNEU1QTIwCgYIKoZIzj0EAwIDRwAwRAIgJEtFo76I3LfgJaLGoxLP-4btvCdKIsEFLjFIUfDosIcCIDQav04cJPILGnPVPazCqfkVtBuyOmsBbx_v-ODn-JDAWQH_MIIB-zCCAaCgAwIBAgIQFZ97ws2JGPEoa5NI-p8z4TAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQxMDAwMDAwMFoYDzIwMzgwNDA5MjM1OTU5WjBJMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxGzAZBgNVBAMMEkZlaXRpYW4gRklETzIgQ0EtMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5-YAnswRZlzKD6w-lv5Qg7lW1XJRHrWzL01mc5V91n2LYXNR3_S7mA5gupuTO5mjQw8xfqIRMHVr1qB3TedY-jZjBkMB0GA1UdDgQWBBRNO9jEZxUbuxPo84TYME-daRXAgzAfBgNVHSMEGDAWgBTRoZhNgX_DuWv2B2e9UBL-kEXxVDASBgNVHRMBAf8ECDAGAQH_AgEAMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEA-3-j0kBHoRFQwnhWbSHMkBaY7KF_TztINFN5ymDkwmUCIQDrCkPBiMHXvYg-kSRgVsKwuVtYonRvC588qRwpLStZ7FkB3DCCAdgwggF-oAMCAQICEBWfe8LNiRjxKGuTSPqfM9YwCgYIKoZIzj0EAwIwSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTAgFw0xODA0MDEwMDAwMDBaGA8yMDQ4MDMzMTIzNTk1OVowSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ3wCm47zF9RMtW-pPlkEHTVTLfSYBlsidz7zOAUiuV6k36PvtKAI_-LZ8MiC9BxQUfUrfpLY6klw344lwLq7POjQjBAMB0GA1UdDgQWBBTRoZhNgX_DuWv2B2e9UBL-kEXxVDAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEAt7E9ZQYxnhfsSk6c1dSmFNnJGoU3eJiycs2DoWh7-IoCIA9iWJH8h-UOAaaPK66DtCLe6GIxdpIMv3kmd1PRpWqsaGF1dGhEYXRhWOSVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EEAAAABQjgyRUQ3M0M4RkI0RTVBMgBgsL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401rpQECAyYgASFYIFkdweEE6mWiIAYPDoKz3881Aoa4sn8zkTm0aPKKYBvdIlggtlG32lxrang8M0tojYJ36CL1VMv2pZSzqR_NfvG88bA"
	// u2fAttestationObj := "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAO-683ISJhKdmUPmVbQuYZsp8lkD7YJcInHS3QOfbrioAiEAzgMJ499cBczBw826r1m55Jmd9mT4d1iEXYS8FbIn8MpjeDVjgVkCSDCCAkQwggEuoAMCAQICBFVivqAwCwYJKoZIhvcNAQELMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAqMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxNDMyNTM0Njg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESzMfdz2BRLmZXL5FhVF-F1g6pHYjaVy-haxILIAZ8sm5RnrgRbDmbxMbLqMkPJH9pgLjGPP8XY0qerrnK9FDCaM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCwYJKoZIhvcNAQELA4IBAQCsFtmzbrazqbdtdZSzT1n09z7byf3rKTXra0Ucq_QdJdPnFhTXRyYEynKleOMj7bdgBGhfBefRub4F226UQPrFz8kypsr66FKZdy7bAnggIDzUFB0-629qLOmeOVeAMmOrq41uxICn3whK0sunt9bXfJTD68CxZvlgV8r1_jpjHqJqQzdio2--z0z0RQliX9WvEEmqfIvHaJpmWemvXejw1ywoglF0xQ4Gq39qB5CDe22zKr_cvKg1y7sJDvHw2Z4Iab_p5WdkxCMObAV3KbAQ3g7F-czkyRwoJiGOqAgau5aRUewWclryqNled5W8qiJ6m5RDIMQnYZyq-FTZgpjXaGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABABo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IiraUBAgMmIAEhWCA1c9AIeH5sN6x1Q-2qR7v255tkeGbWs0ECCDw35kJGBCJYIBjTUxruadjFFMnWlR5rPJr23sBJT9qexY9PCc9o8hmT"
	attestationObj := "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgRvfOaUcMVmHqrKzXSH2Inb4PIshESObwuPrtTS_W3RMCICF_qfvwZhDRF8bqiNGYty2iXcOxY8Tgi7TgQJHZqi4wY3g1Y4FZAlMwggJPMIIBN6ADAgECAgQ8aClNMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAxMS8wLQYDVQQDDCZZdWJpY28gVTJGIEVFIFNlcmlhbCAyMzkyNTczNDgxMTExNzkwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL3fZ5Pbd5TDUDFx7SxNRUrZc2Z1Gki6pdn5tWo6IIF5a07fK817knoUkxD7xGhHb_xXkql9ti-gKGvGoyACDmOjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMA0GCSqGSIb3DQEBCwUAA4IBAQCqwA1RCX7sFaSGs3m8xINA-GfTly7Oamf7pHDjYMZEWfCtOELT_wgeceqJU5cbI_klwK0AwkcxGFIG8LOpGSn7kbdmtT_hM1Iqg1i40SC0q_t_6O8ke2T_xqYhSsHZvnM2_eDzqBg_k0tSGHX14_eJgK-XClseBCo4dtdLqL7v6S3S43PMZEHIlK182aT0fa09pP6vR5GYR1PjWgic5Mvj08g26tCip86lYVrX5EgQhsN3s2ZE0vuZa7zimyGtuJX3k4LuxUk-TsEzwhZ_B3H1mTFzEg_yjVPogaiXQMEyzzw0aCy7z05dvcHggCIfh1KZgUHdFJbXDzqwPyxbwH-taGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAimCIoe8U_N9M1rTGeCqJ96TAu5uqSPa7YUzdh7qq-AdJlnBl8NwCpu2-sNj9UIVH5rAjX_RXlSGTGWKexKIZXKUBAgMmIAEhWCB7XpGVxTYo6jtkxB7sBR4Af_YM0GvInN5V7IvUIilN2yJYINphegJ6kNET_VIp0QOxssW8xxUFEgg5ic3HXmoGg4fS"
	base64Url := base64.RawURLEncoding
	cborByte := make([]byte, base64Url.DecodedLen(len(attestationObj)))
	cborByte, err := base64Url.DecodeString(attestationObj)
	if err != nil {
		log.Error().Err(err).Msg("failed base64 decoding")
	}
	fmt.Println(hex.Dump(cborByte))
	fmt.Println(fmt.Sprintf("%x", cborByte))


	var cbor C
	if err := codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&cbor); err != nil {
		log.Error().Err(err).Msg("failed decoding cbor")
	}

	//fmt.Println(c.Amt)
	//fmt.Println(c.Fun)

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
