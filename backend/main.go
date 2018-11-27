package main

import (
	"net/http"
	"io"
	"log"
	"fmt"
	"math/rand"
	"github.com/gorilla/mux"
	"crypto/sha256"
	"encoding/json"
	"bytes"
)

func main() {
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

	url, _ := s.Get("articleRoute").URL("category", "books", "id", "123")
	fmt.Printf(url.String())

	r.Path("/register").Methods(http.MethodPost).HandlerFunc(RegisterHandler)

	srv := &http.Server{
		Handler: r,//newMux,
		Addr: "127.0.0.1:8000",
	}

	log.Fatalln(srv.ListenAndServe())
}

// WebAuthN Register
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	b := sha256.Sum256([]byte(""))
	challenge := string(b[:])

	r.Body
}

// ServerPublicKeyCredentialCreationOptionsRequest
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsrequest
type ServerPublicKeyCredentialCreationOptionsRequest struct {
	UserName string `json:"username"`
	DisplayName string `json:"displayName"`

	// https://w3c.github.io/webauthn/#authenticatorSelection
	AuthenticatorSelectionCriteria struct{
		RequireResidentKey bool `json:"residentKey"` // default = false
		//https://w3c.github.io/webauthn/#attachment
		//It is Enum with either value {"platform","cross-platform"}
		AuthenticationAttachment string `json:"authenticatorAttachment"`
		//https://w3c.github.io/webauthn/#userVerificationRequirement
		//It is Enum with either value {"required","preferred","discouraged"}
		UserVerificationRequirement string `json:"userVerification"`// default = preferred
	} `json:"authenticatorSelection,omitempty"`

	//https://w3c.github.io/webauthn/#enumdef-attestationconveyancepreference
	//It is Enum with either value {"none","indirect","direct"}
	AttestationConveyancePreference AttestationConveyancePreference `json:"attestation,omitempty"` // default="none"
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
	Required:  "required",
	Preferred:  "preferred",
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
	var uv UserVerificationRequirement
	switch j {
	case "required":
		uv = Required
	case "discouraged":
		uv = Discouraged
	case "preferred":
	default:
		uv = Preferred
	}
	*u = uv
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
	None:  "none",
	Indirect:  "indirect",
	Direct: "direct",
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
	var attestation AttestationConveyancePreference
	switch j {
	case "indirect":
		attestation = Indirect
	case "direct":
		attestation = Direct
	case "none":
	default:
		attestation = None
	}
	*a = attestation
	return nil
}

// ServerPublicKeyCredentialCreationOptionsResponse
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsresponse
type ServerPublicKeyCredentialCreationOptionsResponse struct {
	Challenge string `json:"attestation"`
	PublicKeyCredentialRpEntity struct {
		Name string `json:"name"`
	} `json:"rp"`
	ServerPublicKeyCredentialUserEntity struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	PublicKeyCredentialParameters []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	} `json:"pubKeyCredParams"`

	Timeout   uint64 `json:"timeout,omitempty"`
	ExcludeCredentials []struct{
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"excludeCredentials,omitempty"`
	AuthenticatorSelectionCriteria struct {
		ResidentKey             bool   `json:"residentKey"`
		AuthenticatorAttachment string `json:"authenticatorAttachment"`
		UserVerification        string `json:"userVerification"`
	} `json:"authenticatorSelection,omitempty"`
	Attestation string `json:"attestation,omitempty"`  // default="none"
	// AuthenticationExtensionsClientInputs  struct{} //TODO 一旦無視
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

type CustomServeMux struct {}
func (c *CustomServeMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/" {
		giveRandom(w, r)
		return }
	http.NotFound(w, r)
	return
}

func giveRandom(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Your random number is: %f", rand.Float64())
}