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
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
)

var rp = "Example Corporation"
var uuid = "S3932ee31vKEC0JtJMIQ"
var userName = "kengoscal@gmail.com"
var displayName = "ken5scal"
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
