package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const (
	credentialsFile = ".go-drive-poc/credentials.json"
	tokenFile       = ".go-drive-poc/token.json"
	redirectURI     = "http://127.0.0.1:8080/oauth/callback"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("\tgo run main.go list")
		fmt.Println("\tgo run main.go download <fileID> <localPath>")
		fmt.Println("\tgo run main.go logout (Deletes the token file)")
		return
	}

	command := os.Args[1]

	switch command {
	case "list":
		srv := getClient()
		listFiles(srv)
	case "download":
		if len(os.Args) < 4 {
			log.Fatal("Usage: go run main.go download <fileID> <localPath>")
		}
		srv := getClient()
		downloadFile(srv, os.Args[2], os.Args[3])
	case "export":
		if len(os.Args) < 4 {
			log.Fatal("Usage: go run main.go download <fileID> <localPath>")
		}
		srv := getClient()
		exportFile(srv, os.Args[2], os.Args[3])
	case "logout":
		if err := os.Remove(tokenFile); err == nil {
			fmt.Println("Token deleted. Please run 'list' to re-authorize.")
		} else if os.IsNotExist(err) {
			fmt.Println("Token file not found.")
		} else {
			log.Fatalf("Failed to delete token file: %v", err)
		}
	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}

// --- OAuth Flow Functions ---

func getClient() *drive.Service {
	dir := filepath.Dir(tokenFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("Unable to create application directory: %v", err)
	}

	b, err := os.ReadFile(credentialsFile)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v\n\nDid you put your client secret JSON in %s?", err, credentialsFile)
	}

	creds := struct {
		Installed struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		} `json:"installed"`
	}{}
	if err := json.Unmarshal(b, &creds); err != nil {
		log.Fatalf("Unable to unmarshal client secret file: %v", err)
	}

	config := &oauth2.Config{
		ClientID:     creds.Installed.ClientID,
		ClientSecret: creds.Installed.ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{drive.DriveScope}, // Full Drive Access!
		RedirectURL:  redirectURI,
	}

	// Try to load cached token
	token, err := loadToken()
	if err != nil {
		// Token not found or invalid, start the web flow
		token = getTokenFromWebFlow(config)
		saveToken(token)
	}

	client := config.Client(context.Background(), token)
	srv, err := drive.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Drive client: %v", err)
	}
	return srv
}

func loadToken() (*oauth2.Token, error) {
	f, err := os.Open(tokenFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	token := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(token)
	return token, err
}

func saveToken(token *oauth2.Token) {
	fmt.Printf("Saving new token to %s...\n", tokenFile)
	f, err := os.OpenFile(tokenFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(token)
	if err != nil {
		log.Fatalf("Unable to encode token: %v", err)
	}
}

// getTokenFromWebFlow initiates the Loopback IP/PKCE flow.
func getTokenFromWebFlow(config *oauth2.Config) *oauth2.Token {
	// 1. Prepare for PKCE
	// Generate a high-entropy cryptographically secure Code Verifier.
	verifier := oauth2.GenerateVerifier()
	
	// Derive the Code Challenge from the Verifier.
	// This challenge will be sent to Google's authorization server.
	challenge := oauth2.S256ChallengeFromVerifier(verifier)

	// Generate a random state string to prevent CSRF attacks.
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Unable to generate random state: %v", err)
	}
	state := base64.URLEncoding.EncodeToString(b)

	// 2. Start local HTTP server to capture the redirect
	server := &http.Server{Addr: ":8080"}
	tokenChan := make(chan *oauth2.Token)
	errorChan := make(chan error)

	http.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		// Extract the authorization code and state from the URL query parameters
		code := r.URL.Query().Get("code")
		receivedState := r.URL.Query().Get("state")

		// Security Check: Verify the state parameter matches what we sent
		if receivedState != state {
			http.Error(w, "State mismatch. Possible CSRF attack.", http.StatusForbidden)
			errorChan <- errors.New("state mismatch during authorization")
			return
		}

		// Security Check: Ensure we received an authorization code
		if code == "" {
			http.Error(w, "Authorization code missing.", http.StatusBadRequest)
			errorChan <- errors.New("authorization code missing in callback")
			return
		}

		// Exchange the authorization code for an access token
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// The config.Exchange call automatically sends the Code Verifier,
		// which Google checks against the Code Challenge it received earlier.
		token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))

		if err != nil {
			http.Error(w, "Failed to exchange code for token: "+err.Error(), http.StatusInternalServerError)
			errorChan <- fmt.Errorf("token exchange failed: %w", err)
			return
		}

		// Success! Send the token back to the main thread.
		fmt.Fprint(w, "Authorization successful. You may close this window.")
		tokenChan <- token
	})

	// Start the server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			// This typically happens if the port is already in use.
			errorChan <- fmt.Errorf("could not start http server: %w", err)
		}
	}()
	
	// 3. Generate the authorization URL and open the browser
	// We include the PKCE challenge and a random state for security.
	authURL := config.AuthCodeURL(state,
		oauth2.AccessTypeOffline, // Request a Refresh Token
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	fmt.Printf("Authorization required.\n")
	fmt.Printf("1. Open your browser to the following URL:\n\n%s\n\n", authURL)
	fmt.Printf("2. After authorizing, the browser will redirect and this application will continue.\n")

	// Attempt to open the URL automatically (best effort)
	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Error opening browser: %v\n", err)
	}

	// 4. Wait for the token or an error
	select {
	case token := <-tokenChan:
		// Shut down the temporary server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		return token
	case err := <-errorChan:
		// Shut down the temporary server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		log.Fatalf("Authorization flow failed: %v", err)
		return nil // Should not be reached
	case <-time.After(5 * time.Minute):
		// Timeout if the user takes too long
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		log.Fatal("Authorization timed out after 5 minutes.")
		return nil // Should not be reached
	}
}

// openBrowser attempts to open the URL in the default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch {
	case strings.Contains(os.Getenv("GOPATH"), "windows"): // Simple check for Windows environment
		cmd = exec.Command("cmd", "/c", "start", url)
	case strings.Contains(os.Getenv("GOPATH"), "darwin"): // macOS
		cmd = exec.Command("open", url)
	default: // Linux (or general fallback)
		cmd = exec.Command("xdg-open", url)
	}
	// We don't care about the command's output, just that it was executed.
	return cmd.Start() 
}

// --- Business Logic ---

func listFiles(srv *drive.Service) {
	fmt.Println("Listing files...")

	r, err := srv.Files.List().
		PageSize(20).
		Q("trashed = false").
		Fields("nextPageToken, files(id, name, mimeType, size, modifiedTime)").
		Do()

	if err != nil {
		log.Fatalf("Unable to retrieve files: %v", err)
	}

	if len(r.Files) == 0 {
		fmt.Println("No files found.")
		return
	}

	fmt.Println("Files:")
	for _, f := range r.Files {
		fmt.Printf("- %s (ID: %s, Mime: %s)\n", f.Name, f.Id, f.MimeType)
	}
}

func downloadFile(srv *drive.Service, fileID string, dest string) {
	resp, err := srv.Files.Get(fileID).Download()
	if err != nil {
		log.Fatalf("Unable to download file: %v", err)
	}
	defer resp.Body.Close()

	out, err := os.Create(dest)
	if err != nil {
		log.Fatalf("Unable to create file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Fatalf("Unable to write file: %v", err)
	}
}

func exportFile(srv *drive.Service, fileID string, dest string) {
	// TODO: Replace hard-coded MIME-type that I set for testing with a specific file
	resp, err := srv.Files.Export(fileID,"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet").Download()
	if err != nil {
		log.Fatalf("Unable to download file: %v", err)
	}
	defer resp.Body.Close()

	out, err := os.Create(dest)
	if err != nil {
		log.Fatalf("Unable to create file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Fatalf("Unable to write file: %v", err)
	}
}