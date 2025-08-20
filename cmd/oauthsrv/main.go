package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type OAuth2Config struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	AuthURL      string `yaml:"auth_url"`
	TokenURL     string `yaml:"token_url"`
	RedirectURI  string `yaml:"redirect_uri"`
	Scopes       string `yaml:"scopes"`
}

var (
	configPath string
	tokensPath string
)

func main() {
	configPath = filepath.Join(".", "cfg.yml")
	tokensPath = filepath.Join(".", "tokens.yml")

	// Ensure tokens file exists
	if _, err := os.Stat(tokensPath); os.IsNotExist(err) {
		if err := os.WriteFile(tokensPath, []byte{}, 0644); err != nil {
			log.Fatalf("Failed to create tokens file: %v", err)
		}
	}

	http.HandleFunc("/", serveMainPage)
	http.HandleFunc("/save", saveConfig)
	http.HandleFunc("/start-pkce", startPKCEFlow)
	http.HandleFunc("/callback", handleCallback)

	port := "8080"
	fmt.Printf("Server starting on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

type TokenResponse struct {
	Timestamp    time.Time `yaml:"timestamp"`
	StatusCode   int       `yaml:"status_code"`
	ResponseBody string    `yaml:"response_body"`
}

func serveMainPage(w http.ResponseWriter, r *http.Request) {
	config := readConfig()

	// Read token responses
	tokenResponses := readTokenResponses()

	// Build token responses HTML
	tokenResponsesHTML := buildTokenResponsesHTML(tokenResponses)

	htmlTemplate := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>OAuth2 PKCE Test</title>
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
		<link href="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/styles/github-dark.min.css" rel="stylesheet">
		<style>
			body {
				background-color: #121212;
				color: #e0e0e0;
			}
			.card {
				background-color: #1e1e1e;
				color: #e0e0e0;
			}
			.form-control, .form-control:focus {
				background-color: #2c2c2c;
				color: #e0e0e0;
				border-color: #444;
			}
			.accordion-button {
				background-color: #2c2c2c;
				color: #e0e0e0;
			}
			.accordion-button:not(.collapsed) {
				background-color: #3c3c3c;
				color: #e0e0e0;
			}
			pre {
				background-color: #1e1e1e;
				color: #e0e0e0;
				padding: 15px;
				border-radius: 5px;
			}
		</style>
	</head>
	<body>
		<div class="container mt-5">
			<h1 class="mb-4">OAuth2 PKCE Flow Tester</h1>
			<form action="/save" method="post" class="mb-4">
				<div class="row mb-3 align-items-center">
					<div class="col-3 text-end">
						<label for="client_id" class="col-form-label">Client ID</label>
					</div>
					<div class="col-9">
						<input type="text" class="form-control" id="client_id" name="client_id" value="%s">
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-3 text-end">
						<label for="client_secret" class="col-form-label">Client Secret</label>
					</div>
					<div class="col-9">
						<input type="text" class="form-control" id="client_secret" name="client_secret" value="%s">
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-3 text-end">
						<label for="auth_url" class="col-form-label">Authorization URL</label>
					</div>
					<div class="col-9">
						<input type="text" class="form-control" id="auth_url" name="auth_url" value="%s">
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-3 text-end">
						<label for="token_url" class="col-form-label">Token URL</label>
					</div>
					<div class="col-9">
						<input type="text" class="form-control" id="token_url" name="token_url" value="%s">
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-3 text-end">
						<label for="redirect_uri" class="col-form-label">Redirect URI</label>
					</div>
					<div class="col-9">
						<input type="text" class="form-control" id="redirect_uri" name="redirect_uri" value="%s">
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-3 text-end">
						<label for="scopes" class="col-form-label">Scopes (space-separated)</label>
					</div>
					<div class="col-9">
						<input type="text" class="form-control" id="scopes" name="scopes" value="%s">
					</div>
				</div>
				<div class="text-center">
					<button type="submit" class="btn btn-primary w-50">Save Configuration</button>
				</div>
			</form>
			<form action="/start-pkce" method="post" class="text-center">
				<button type="submit" class="btn btn-success w-50">Start PKCE Flow</button>
			</form>

			<div class="mt-5">
				<h2>Token Responses</h2>
				%s
			</div>
		</div>
		<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
		<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/highlight.min.js"></script>
		<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/languages/json.min.js"></script>
		<script>
			hljs.highlightAll();
		</script>
	</body>
	</html>`

	fmt.Fprintf(w, htmlTemplate,
		config.ClientID,
		config.ClientSecret,
		config.AuthURL,
		config.TokenURL,
		config.RedirectURI,
		fmt.Sprintf("%v", config.Scopes),
		tokenResponsesHTML,
	)
}

func saveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := OAuth2Config{
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		AuthURL:      r.FormValue("auth_url"),
		TokenURL:     r.FormValue("token_url"),
		RedirectURI:  r.FormValue("redirect_uri"),
		Scopes:       strings.TrimSpace(r.FormValue("scopes")),
	}

	// Ensure directory exists
	os.MkdirAll(filepath.Dir(configPath), 0755)

	// Write config to YAML
	yamlData, err := yaml.Marshal(&config)
	if err != nil {
		http.Error(w, "Failed to marshal config", http.StatusInternalServerError)
		return
	}

	err = os.WriteFile(configPath, yamlData, 0644)
	if err != nil {
		http.Error(w, "Failed to write config", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func readConfig() OAuth2Config {
	config := OAuth2Config{}

	// Check if config file exists
	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		return config
	}

	// Read config file
	yamlData, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Error reading config: %v", err)
		return config
	}

	// Provide default values if config is empty
	if len(yamlData) == 0 {
		return config
	}

	err = yaml.Unmarshal(yamlData, &config)
	if err != nil {
		log.Printf("Error parsing config: %v", err)
		return config
	}

	return config
}

func startPKCEFlow(w http.ResponseWriter, r *http.Request) {
	// Read configuration
	config := readConfig()

	// Generate PKCE code verifier and challenge
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Prepare authorization request
	params := url.Values{
		"client_id":             {config.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {config.RedirectURI},
		"scope":                 {config.Scopes},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	// Construct full authorization URL
	authorizationURL := fmt.Sprintf("%s?%s", config.AuthURL, params.Encode())

	// Store code verifier in session (for this example, we'll use a cookie)
	http.SetCookie(w, &http.Cookie{
		Name:  "pkce_code_verifier",
		Value: codeVerifier,
		Path:  "/",
	})

	// Debug logging
	log.Printf("Authorization Request Details:\n"+
		"Client ID: %s\n"+
		"Redirect URI: %s\n"+
		"Scope: %s\n"+
		"Authorization URL: %s\n",
		config.ClientID, config.RedirectURI, config.Scopes, authorizationURL)

	// Add a hidden field to render the authorization URL for debugging
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Starting PKCE Flow</title>
			<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
		</head>
		<body>
			<div class="container mt-5">
				<h1 class="mb-4">Starting PKCE Flow</h1>
				<div class="alert alert-info">
					If not redirected automatically, click the link below:
				</div>
				<a href="%s" class="btn btn-primary mb-3">Start Authorization</a>
				<div class="card">
					<div class="card-header">Debug Information</div>
					<div class="card-body">
						<pre class="card-text">Authorization URL: %s</pre>
					</div>
				</div>
			</div>
			<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
		</body>
		</html>`,
		authorizationURL, authorizationURL)

	// Uncomment the following line to manually trigger redirect if automatic redirect fails
	// http.Redirect(w, r, authorizationURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Read configuration
	config := readConfig()

	// Get the authorization code from the query parameters
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No authorization code received", http.StatusBadRequest)
		return
	}

	// Retrieve the code verifier from the cookie
	codeVerifierCookie, err := r.Cookie("pkce_code_verifier")
	if err != nil {
		http.Error(w, "No code verifier found", http.StatusBadRequest)
		return
	}

	// Prepare token request
	params := url.Values{
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {config.RedirectURI},
		"code_verifier": {codeVerifierCookie.Value},
	}

	// Send token request
	resp, err := http.PostForm(config.TokenURL, params)
	if err != nil {
		http.Error(w, "Failed to request token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read token response", http.StatusInternalServerError)
		return
	}

	// Save token response
	tokenResponse := TokenResponse{
		Timestamp:    time.Now(),
		StatusCode:   resp.StatusCode,
		ResponseBody: formatJSONResponse(body),
	}
	saveTokenResponse(tokenResponse)

	// Display response details
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>OAuth2 Token Response</title>
			<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
		</head>
		<body>
			<div class="container mt-5">
				<h1 class="mb-4">OAuth2 Token Response</h1>
				<div class="card">
					<div class="card-header">
						Status Code: %d
					</div>
					<div class="card-body">
						<pre class="card-text language-json">%s</pre>
					</div>
				</div>
				<a href="/" class="btn btn-primary mt-3">Back to Home</a>
			</div>
			<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
		</body>
		</html>`,
		resp.StatusCode,
		string(body),
	)
}

func saveTokenResponse(tokenResponse TokenResponse) {
	// Read existing token responses
	tokenResponses := readTokenResponses()

	// Add new token response
	tokenResponses = append(tokenResponses, tokenResponse)

	// Sort token responses by timestamp in descending order
	sort.Slice(tokenResponses, func(i, j int) bool {
		return tokenResponses[i].Timestamp.After(tokenResponses[j].Timestamp)
	})

	// Write back to file
	yamlData, err := yaml.Marshal(tokenResponses)
	if err != nil {
		log.Printf("Failed to marshal token responses: %v", err)
		return
	}

	if err := os.WriteFile(tokensPath, yamlData, 0644); err != nil {
		log.Printf("Failed to write token responses: %v", err)
	}
}

func readTokenResponses() []TokenResponse {
	// Read tokens file
	yamlData, err := os.ReadFile(tokensPath)
	if err != nil {
		log.Printf("Failed to read tokens file: %v", err)
		return []TokenResponse{}
	}

	// If file is empty or contains only whitespace, return empty slice
	if len(strings.TrimSpace(string(yamlData))) == 0 {
		return []TokenResponse{}
	}

	// Unmarshal token responses
	var tokenResponses []TokenResponse
	if err := yaml.Unmarshal(yamlData, &tokenResponses); err != nil {
		log.Printf("Failed to unmarshal token responses: %v", err)
		return []TokenResponse{}
	}

	return tokenResponses
}

func buildTokenResponsesHTML(tokenResponses []TokenResponse) string {
	if len(tokenResponses) == 0 {
		return `<div class="alert alert-info">No token responses yet</div>`
	}

	var htmlBuilder strings.Builder
	htmlBuilder.WriteString(`<div class="accordion" id="tokenResponses">`)

	for i, response := range tokenResponses {
		htmlBuilder.WriteString(fmt.Sprintf(`
		<div class="accordion-item border border-secondary">
			<h2 class="accordion-header border border-secondary">
				<button class="accordion-button %s" type="button" data-bs-toggle="collapse" data-bs-target="#response-%d">
					Response from %s (Status Code: %d)
				</button>
			</h2>
			<div id="response-%d" class="accordion-collapse collapse %s border border-secondary">
				<div class="accordion-body bg-secondary">
					<pre>%s</pre>
				</div>
			</div>
		</div>`,
			map[bool]string{true: "collapsed", false: ""}[i != 0],
			i,
			response.Timestamp.Format(time.RFC3339),
			response.StatusCode,
			i,
			map[bool]string{true: "", false: "show"}[i != 0],
			response.ResponseBody,
		))
	}

	htmlBuilder.WriteString(`
		</div>`)

	return htmlBuilder.String()
}

// generateCodeVerifier creates a random PKCE code verifier
func generateCodeVerifier() string {
	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Encode to base64 URL-safe without padding
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

// generateCodeChallenge creates a code challenge from the code verifier
func generateCodeChallenge(codeVerifier string) string {
	// Create SHA256 hash of the code verifier
	hashBytes := sha256.Sum256([]byte(codeVerifier))

	// Encode to base64 URL-safe without padding
	return base64.RawURLEncoding.EncodeToString(hashBytes[:])
}

// formatJSONResponse pretty prints and formats JSON
func formatJSONResponse(body []byte) string {
	var prettyJSON bytes.Buffer

	// Check if the body is already valid JSON
	var jsonObj interface{}
	if err := json.Unmarshal(body, &jsonObj); err != nil {
		// If not valid JSON, return original string
		return string(body)
	}

	// Pretty print JSON
	if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
		// If indentation fails, return original string
		return string(body)
	}

	return prettyJSON.String()
}
