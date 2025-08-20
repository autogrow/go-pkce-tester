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
	"strconv"
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

func handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	// Read configuration
	config := readConfig()

	// Get the refresh token from the request
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		http.Error(w, "No refresh token provided", http.StatusBadRequest)
		return
	}

	// Prepare refresh token request
	params := url.Values{
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	// Send refresh token request
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
		<html lang="en" data-bs-theme="dark">;
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>OAuth2 Refresh Token Response</title>
			<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
			<link href="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/styles/github-dark.min.css" rel="stylesheet">
		</head>
		<body class="bg-dark text-white">
			<div class="container mt-5">
				<h1 class="mb-4 text-center">OAuth2 Refresh Token Response</h1>
				<div class="card bg-secondary text-white">
					<div class="card-header">
						Status Code: %d
					</div>
					<div class="card-body">
						<pre class="bg-dark text-white"><code class="language-json">%s</code></pre>
					</div>
				</div>
				<a href="/" class="btn btn-primary mt-3">Back to Home</a>
			</div>
			<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/highlight.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/languages/json.min.js"></script>
			<script>
				hljs.highlightAll();
			</script>
		</body>
		</html>`,
		resp.StatusCode,
		string(body),
	)
}

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
	http.HandleFunc("/refresh-token", handleRefreshToken)
	http.HandleFunc("/request-token", handleManualTokenRequest)

	port := "8080"
	fmt.Printf("Server starting on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleManualTokenRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read configuration
	config := readConfig()

	// Get the code and code verifier from the form
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")

	// Prepare token request
	params := url.Values{
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {config.RedirectURI},
		"code_verifier": {codeVerifier},
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

	trp := TokenResponsePayload{}
	if err := json.Unmarshal(body, &trp); err != nil {
		http.Error(w, "Failed to unmarshal token response", http.StatusInternalServerError)
		return
	}

	var alertBanner string
	if resp.StatusCode != http.StatusOK {
		alertBanner = `<div class="alert alert-danger" role="alert"><p>Failed to request token as it returned status code: ` + strconv.Itoa(resp.StatusCode) + ` - more details below</p></div>`
	}

	// Display response details
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en" data-bs-theme="dark">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>OAuth2 Token Response</title>
			<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
			<link href="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/styles/github-dark.min.css" rel="stylesheet">
		</head>
		<body class="bg-dark text-white">
			<div class="container mt-5">
				<h1 class="mb-4">OAuth2 Token Response</h1>

				%s

				<p class="lead">The remote authorization server has responded with the following details. This marks the end of the flow.</p>

				<div class="card bg-secondary text-white">
					<div class="card-header fs-4">
						Response JSON (Status Code: %d)
					</div>
					<div class="card-body">
						<pre class="bg-dark text-white p-3"><code class="language-json">%s</code></pre>
					</div>
				</div>

				<div class="card bg-secondary text-white mt-3">
					<div class="card-header fs-4">
						Response Fields
					</div>
					<div class="card-body">
						<table class="table table-dark">
							<thead>
								<tr>
									<th scope="col">Field</th>
									<th scope="col">Value</th>
									<th scope="col">Explanation</th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td><code>access_token</code></td>
									<td><code>%s</code></td>
									<td>Access token used for subsequent requests in the Authorization header</td>
								</tr>
								<tr>
									<td><code>token_type</code></td>
									<td><code>%s</code></td>
									<td>How the token should be used by the client to access the server</td>
								</tr>
								<tr>
									<td><code>expires_in</code></td>
									<td><code>%d</code></td>
									<td>How long until the token expires</td>
								</tr>
								<tr>
									<td><code>refresh_token</code></td>
									<td><code>%s</code></td>
									<td>The token used to refresh the access token when it expires</td>
								</tr>
								<tr>
									<td><code>scope</code></td>
									<td><code>%s</code></td>
									<td>The OAuth scopes the token was issued for</td>
								</tr>
								<tr>
									<td><code>created_at</code></td>
									<td><code>%d</code></td>
									<td>Created at (Unix timestamp)</td>
								</tr>
								<tr>
									<td><code>id_token</code></td>
									<td><code>%s</code></td>
									<td>JWT token that can be decoded to get info about the user</td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>

				<div class="mt-3">
					<a href="/" class="btn btn-primary btn-lg">Done</a>
				</div>
			</div>
			<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/highlight.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/languages/json.min.js"></script>
			<script>
				hljs.highlightAll();
			</script>
		</body>
		</html>`,
		alertBanner,
		resp.StatusCode,
		tokenResponse.ResponseBody,
		trp.AccessToken,
		trp.TokenType,
		trp.ExpiresIn,
		trp.RefreshToken,
		trp.Scope,
		trp.CreatedAt,
		trp.IDToken[:30]+"...",
	)
}

type TokenResponsePayload struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	CreatedAt    int    `json:"created_at"`
	IDToken      string `json:"id_token"`
}

type TokenResponse struct {
	Timestamp    time.Time `yaml:"timestamp"`
	StatusCode   int       `yaml:"status_code"`
	ResponseBody string    `yaml:"response_body"`
	RefreshToken string    `yaml:"refresh_token,omitempty"`
}

func serveMainPage(w http.ResponseWriter, r *http.Request) {
	config := readConfig()

	// Read token responses
	tokenResponses := readTokenResponses()

	// Build token responses HTML
	tokenResponsesHTML := buildTokenResponsesHTML(tokenResponses)

	htmlTemplate := `<!DOCTYPE html>
	<html lang="en" data-bs-theme="dark">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>OAuth2 PKCE Test</title>
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
		<link href="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/styles/github-dark.min.css" rel="stylesheet">
		<style>
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
			<h1 class="mb-4 text-center">OAuth2 PKCE Flow Tester</h1>
			<p class="lead text-center">We are the application/client and we need to request authorization from the remote authorization server.</p>
			<form action="/save" method="post" class="mb-4">
				<div class="row mb-3 align-items-center">
					<div class="col-2 text-end">
						<label for="client_id" class="col-form-label">Client ID</label>
					</div>
					<div class="col-5">
						<input type="text" class="form-control bg-dark text-white" id="client_id" name="client_id" value="%s">
					</div>
					<div class="col-5">
						<label for="client_id" class="col-form-label">Client ID from the authorization server</label>
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-2 text-end">
						<label for="client_secret" class="col-form-label">Client Secret</label>
					</div>
					<div class="col-5">
						<input type="text" class="form-control bg-dark text-white" id="client_secret" name="client_secret" value="%s">
					</div>
					<div class="col-5">
						<label for="client_secret" class="col-form-label">Client Secret from the authorization server</label>
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-2 text-end">
						<label for="auth_url" class="col-form-label">Authorization URL</label>
					</div>
					<div class="col-5">
						<input type="text" class="form-control bg-dark text-white" id="auth_url" name="auth_url" value="%s">
					</div>
					<div class="col-5">
						<label for="auth_url" class="col-form-label">URL to /oauth/authorize on the authorization server</label>
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-2 text-end">
						<label for="token_url" class="col-form-label">Token URL</label>
					</div>
					<div class="col-5">
						<input type="text" class="form-control bg-dark text-white" id="token_url" name="token_url" value="%s">
					</div>
					<div class="col-5">
						<label for="token_url" class="col-form-label">URL to /oauth/token on the authorization server</label>
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-2 text-end">
						<label for="redirect_uri" class="col-form-label">Redirect URI</label>
					</div>
					<div class="col-5">
						<input type="text" class="form-control bg-dark text-white" id="redirect_uri" name="redirect_uri" value="%s">
					</div>
					<div class="col-5">
						<label for="redirect_uri" class="col-form-label">URI for the authorization server to send us back here</label>
					</div>
				</div>
				<div class="row mb-3 align-items-center">
					<div class="col-2 text-end">
						<label for="scopes" class="col-form-label">Scopes (space-separated)</label>
					</div>
					<div class="col-5">
						<input type="text" class="form-control bg-dark text-white" id="scopes" name="scopes" value="%s">
					</div>
					<div class="col-5">
						<label for="scopes" class="col-form-label">Scopes to request from the authorization server</label>
					</div>
				</div>
				<div class="text-center">
					<button type="submit" class="btn btn-primary w-50">Save Configuration</button>
				</div>
			</form>
			<form action="/start-pkce" method="post" class="text-center">
				<button type="submit" class="btn btn-success w-50">Start PKCE Flow</button>
			</form>

			<div class="mt-5 mb-3">
				<h2>Token Responses</h2>
				%s
			</div>
		</div>
		<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
		<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/highlight.min.js"></script>
		<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/languages/json.min.js"></script>
		<script type="text/javascript">
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
		<html lang="en" data-bs-theme="dark">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Starting PKCE Flow</title>
			<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
			<link href="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/styles/github-dark.min.css" rel="stylesheet">
			<style>
				.copy-btn {
					position: absolute;
					top: 10px;
					right: 10px;
				}
			</style>
		</head>
		<body class="bg-dark text-white">
			<div class="container mt-5">
				<h1 class="mb-4">Starting PKCE Flow</h1>

				<p class="lead">These are the fields that we use to start the PKCE flow.  A requirement is for this client application to generate a code verifier and challenge.</p>
				
				<div class="card bg-secondary text-white mb-3">
					<div class="card-header fs-4">Challenge Codes</div>
					<div class="card-body">
						<p>These codes are required to be generated by this client application and used in the PKCE flow.  We have generated the below:</p>
						<table class="table table-dark table-bordered">
							<tbody>
								<tr>
									<td>Code Verifier</td>
									<td><code>%s</code></td>
									<td>Used to generate the code challenge</td>
								</tr>
								<tr>
									<td>Code Challenge</td>
									<td><code>%s</code></td>
									<td>Authorization server uses this to verify the authorization request</td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>

				<div class="card bg-secondary text-white position-relative mb-3">
					<div class="card-header fs-4">Authorization URL</div>
					<div class="card-body">
						<p>This is the authorization URL that the user will be redirected to, but you can use the button below:</p>
						<pre class="p-2 bg-dark" id="authUrl">%s</pre>
						<button class="btn btn-sm btn-outline-light copy-btn" onclick="copyToClipboard()">Copy</button>
					</div>
				</div>

				<div class="card bg-secondary text-white mb-3">
					<div class="card-header fs-4">Query Parameters</div>
					<div class="card-body">
						<p>These are query parameters from the URL laid out and explained:</p>
						<table class="table table-dark table-bordered">
							<thead>
								<tr>
									<th>Parameter</th>
									<th>Value</th>
									<th>Description</th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td><code>client_id</code></td>
									<td><code>%s</code></td>
									<td>The ID of the client application registered with the authorization server</td>
								</tr>
								<tr>
									<td><code>response_type</code></td>
									<td><code>code</code></td>
									<td>Indicates the client wants to receive an authorization code</td>
								</tr>
								<tr>
									<td><code>redirect_uri</code></td>
									<td><code>%s</code></td>
									<td>The URI where the authorization server will redirect after processing the request</td>
								</tr>
								<tr>
									<td><code>scope</code></td>
									<td><code>%s</code></td>
									<td>The specific permissions the application is requesting</td>
								</tr>
								<tr>
									<td><code>code_challenge</code></td>
									<td><code>%s</code></td>
									<td>A derivative of the code verifier used for PKCE (Proof Key for Code Exchange)</td>
								</tr>
								<tr>
									<td><code>code_challenge_method</code></td>
									<td><code>S256</code></td>
									<td>The method used to generate the code challenge (SHA-256 hashing)</td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>

				<a href="%s" class="btn btn-primary mb-3 btn-lg">Start Authorization</a>
			</div>
			<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/highlight.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/languages/json.min.js"></script>
			<script>
				hljs.highlightAll();

				function copyToClipboard() {
					const authUrl = document.getElementById('authUrl').textContent;
					navigator.clipboard.writeText(authUrl).then(() => {
						alert('Authorization URL copied to clipboard!');
					}, (err) => {
						console.error('Could not copy text: ', err);
					});
				}
			</script>
		</body>
		</html>`,
		codeVerifier,
		codeChallenge,
		authorizationURL,
		config.ClientID,
		config.RedirectURI,
		config.Scopes,
		codeChallenge,
		authorizationURL)

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

	// Generate payload as JSON for display
	payloadJSON, _ := json.MarshalIndent(map[string]string{
		"client_id":     config.ClientID,
		"client_secret": config.ClientSecret,
		"code":          code,
		"grant_type":    "authorization_code",
		"redirect_uri":  config.RedirectURI,
		"code_verifier": codeVerifierCookie.Value,
	}, "", "  ")

	// Display response details
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en" data-bs-theme="dark">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>OAuth2 Callback</title>
			<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
			<link href="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/styles/github-dark.min.css" rel="stylesheet">
		</head>
		<body class="bg-dark text-white">
			<div class="container mt-5">
				<h1 class="mb-4">OAuth2 Callback Received</h1>
				<p class="lead">The user clicked authorize and the authorization server has redirected back to this page with a code to use to request an access token.</p>
				<div class="card bg-secondary text-white mb-3">
					<div class="card-header fs-4">Authorization Code</div>
					<div class="card-body">
						<p>This is the code given by the authorization server that we will use in the next request</p>
						<pre class="bg-dark text-white p-3"><code class="language-text">%s</code></pre>
					</div>
				</div>

				<div class="card bg-secondary text-white mb-3">
					<div class="card-header fs-4">Token Request Payload</div>
					<div class="card-body">
						<p>This is full payload that will be sent in the request body to the authorization server for the next step</p>
						<pre class="bg-dark text-white p-3"><code class="language-json">%s</code></pre>
					</div>
				</div>

				<div class="card bg-secondary text-white mb-3">
					<div class="card-header fs-4">Request Fields</div>
					<div class="card-body">
						<table class="table table-dark table-bordered">
							<thead>
								<tr>
									<th>Parameter</th>
									<th>Value</th>
									<th>Description</th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td><code>client_id</code></td>
									<td><code>%s</code></td>
									<td>The ID of the client application registered with the authorization server</td>
								</tr>
								<tr>
									<td><code>client_secret</code></td>
									<td><code>%s</code></td>
									<td>The secret of the client application registered with the authorization server</td>
								</tr>
								<tr>
									<td><code>code</code></td>
									<td><code>%s</code></td>
									<td>The authorization code received from the authorization server</td>
								</tr>
								<tr>
									<td><code>code_verifier</code></td>
									<td><code>%s</code></td>
									<td>The code verifier used to generate the authorization code</td>
								</tr>
								<tr>
									<td><code>grant_type</code></td>
									<td><code>authorization_code</code></td>
									<td>The type of grant being requested</td>
								</tr>
								<tr>
									<td><code>redirect_uri</code></td>
									<td><code>%s</code></td>
									<td>The redirect URI registered with the authorization server</td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>

				<form action="/request-token" method="post" class="mb-3">
					<input type="hidden" name="code" value="%s">
					<input type="hidden" name="code_verifier" value="%s">
					<button type="submit" class="btn btn-primary btn-lg">Request Access Token</button>
					<a href="/" class="btn btn-secondary btn-lg">Back to Home</a>
				</form>

			</div>
			<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/highlight.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.7.0/lib/languages/json.min.js"></script>
			<script>
				hljs.highlightAll();
			</script>
		</body>
		</html>`,
		code,
		string(payloadJSON),

		config.ClientID,
		config.ClientSecret,
		code,
		codeVerifierCookie.Value,
		config.RedirectURI,

		code,
		codeVerifierCookie.Value,
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
		// Extract refresh token from response body
		var refreshTokenButton string
		var parsedResponse map[string]interface{}
		if err := json.Unmarshal([]byte(response.ResponseBody), &parsedResponse); err == nil {
			if rt, ok := parsedResponse["refresh_token"].(string); ok && rt != "" {
				refreshTokenButton = fmt.Sprintf(`
					<form action="/refresh-token" method="post" class="mt-3">
						<input type="hidden" name="refresh_token" value="%s">
						<button type="submit" class="btn btn-primary">Refresh Token</button>
					</form>`, rt)
			}
		}
		_ = refreshTokenButton

		badgeColor := "danger"
		if response.StatusCode == 200 {
			badgeColor = "success"
		}

		htmlBuilder.WriteString(fmt.Sprintf(`
		<div class="accordion-item border border-secondary">
			<h2 class="accordion-header border border-secondary">
				<button class="accordion-button %s" type="button" data-bs-toggle="collapse" data-bs-target="#response-%d">
					<span class="badge bg-%s me-2">%d</span> Response from %s
				</button>
			</h2>
			<div id="response-%d" class="accordion-collapse collapse %s border border-secondary">
				<div class="accordion-body bg-secondary">
					<pre><code class="language-json">%s</code></pre>
					%s
				</div>
			</div>
		</div>`,
			map[bool]string{true: "collapsed", false: ""}[i != 0],
			i,
			badgeColor,
			response.StatusCode,
			response.Timestamp.Format("Jan 02 15:04:05"),
			i,
			map[bool]string{true: "", false: "show"}[i != 0],
			response.ResponseBody,
			refreshTokenButton,
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
