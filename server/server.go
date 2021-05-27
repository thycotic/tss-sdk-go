package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	cloudBaseURLTemplate string = "https://%s.secretservercloud.%s/"
	defaultAPIPathURI    string = "/api/v1"
	defaultTokenPathURI  string = "/oauth2/token"
	defaultTLD           string = "com"
)

// UserCredential holds the username and password that the API should use to
// authenticate to the REST API
type UserCredential struct {
	Username, Password string
}

// Configuration settings for the API
type Configuration struct {
	Credentials                                              UserCredential
	ServerURL, TLD, Tenant, apiPathURI, tokenPathURI, Domain string
}

// Server provides access to secrets stored in Thycotic Secret Server
type Server struct {
	Configuration
}

// New returns an initialized Secrets object
func New(config Configuration) (*Server, error) {
	if config.ServerURL == "" && config.Tenant == "" || config.ServerURL != "" && config.Tenant != "" {
		return nil, fmt.Errorf("Either ServerURL or Tenant must be set")
	}
	if config.TLD == "" {
		config.TLD = defaultTLD
	}
	if config.apiPathURI == "" {
		config.apiPathURI = defaultAPIPathURI
	}
	config.apiPathURI = strings.Trim(config.apiPathURI, "/")
	if config.tokenPathURI == "" {
		config.tokenPathURI = defaultTokenPathURI
	}
	config.tokenPathURI = strings.Trim(config.tokenPathURI, "/")
	return &Server{config}, nil
}

// urlFor is the URL for the given resource and path
func (s Server) urlFor(resource, path string) string {
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}

	switch {
	case resource == "token":
		return fmt.Sprintf("%s/%s", baseURL, s.tokenPathURI)
	case path != "/":
		path = strings.TrimLeft(path, "/")
		fallthrough
	default:
		return fmt.Sprintf("%s/%s/%s/%s", baseURL, s.apiPathURI, strings.Trim(resource, "/"), path)
	}
}

// accessResource uses the accessToken to access the API resource.
// It assumes an appropriate combination of method, resource, path and input.
func (s Server) accessResource(method, resource, path string, input interface{}) ([]byte, error) {
	switch resource {
	case "secrets":
	default:
		message := "unknown resource"

		log.Printf("[DEBUG] %s: %s", message, resource)
		return nil, fmt.Errorf(message)
	}

	body := bytes.NewBuffer([]byte{})

	if input != nil {
		if data, err := json.Marshal(input); err == nil {
			body = bytes.NewBuffer(data)
		} else {
			log.Print("[DEBUG] marshaling the request body to JSON:", err)
			return nil, err
		}
	}

	req, err := http.NewRequest(method, s.urlFor(resource, path), body)

	if err != nil {
		log.Printf("[DEBUG] creating req: %s /%s/%s: %s", method, resource, path, err)
		return nil, err
	}

	accessToken, err := s.getAccessToken()

	if err != nil {
		log.Print("[DEBUG] error getting accessToken:", err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	switch method {
	case "POST", "PUT":
		req.Header.Set("Content-Type", "application/json")
	}

	log.Printf("[DEBUG] calling %s", req.URL.String())

	data, _, err := handleResponse((&http.Client{}).Do(req))

	return data, err
}

// getAccessToken gets an OAuth2 Access Grant and returns the token
// endpoint and get an accessGrant.
func (s Server) getAccessToken() (string, error) {
	body := strings.NewReader(url.Values{
		"username":   {s.Credentials.Username},
		"password":   {s.Credentials.Password},
		"domain":     {s.Domain},
		"grant_type": {"password"},
	}.Encode())
	data, _, err := handleResponse(http.Post(s.urlFor("token", ""), "application/x-www-form-urlencoded", body))

	if err != nil {
		log.Print("[DEBUG] grant response error:", err)
		return "", err
	}

	grant := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}{}

	if err = json.Unmarshal(data, &grant); err != nil {
		log.Print("[INFO] parsing grant response:", err)
		return "", err
	}
	return grant.AccessToken, nil
}
