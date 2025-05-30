package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DIMO-Network/shared/pkg/settings"
	dex "github.com/DIMO-Network/token-exchange-api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
)

// privilege prefix to denote the 1:1 mapping to bit values and to make them easier to deprecate if desired in the future
var PermissionMap = map[int]string{
	1: "privilege:GetNonLocationHistory",  // All-time non-location data
	2: "privilege:ExecuteCommands",        // Commands
	3: "privilege:GetCurrentLocation",     // Current location
	4: "privilege:GetLocationHistory",     // All-time location
	5: "privilege:GetVINCredential",       // View VIN credential
	6: "privilege:GetLiveData",            // Subscribe live data
	7: "privilege:GetRawData",             // Raw data
	8: "privilege:GetApproximateLocation", // Approximate location
}

func main() {
	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "token-exchange-api").
		Logger()

	signedDoc := signDocument("settings.yaml", "sacd/permission01.json", &logger)
	res, err := uploadSigned(signedDoc)

	fmt.Println("SUCCESS: ", res, err)

	// cid, err := uploadSACDAgreement("sacd/permission01.json")
	// if err != nil {
	// 	log.Fatalf("Failed to upload SACD: %v", err)
	// }
	// fmt.Printf("IPFS CID: %s", cid)

	// jwt := getJwtToken()
	// resp, err := postTokenExchange(jwt)
	// if err != nil {
	// 	log.Fatalf("Failed to token exchange: %v", err)
	// }
	// fmt.Printf("\n")
	// fmt.Println(resp)

	// body, err := fetchFromIPj
	// fmt.Printf("%s", body)

	// var record models.PermissionRecord
	// if err := json.Unmarshal(body, &record); err != nil {
	// 	fmt.Errorf("invalid JSON format: %w", err)
	// }
	// fmt.Print(record)

	// address := common.HexToAddress("0x15b8aB8022eDA0B9b15D78EC7b39Df795fa30ff2")
	// res, err := evaluateSacdDoc(&record, []int64{1, 2, 3, 4}, &address)
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }
	// fmt.Print(res)
}

func getJwtToken() string {
	// Load .env file
	// First try from the current directory
	err := godotenv.Load()
	if err != nil {
		// If not found, try from the project root
		projectRoot := filepath.Join(filepath.Dir(os.Args[0]), "../..")
		err = godotenv.Load(filepath.Join(projectRoot, ".env"))
		if err != nil {
			log.Println("Warning: .env file not found, using environment variables")
		}
	}

	// Parse the DEX URL
	dexURLStr := os.Getenv("DEX_URL")
	if dexURLStr == "" {
		log.Fatalf("Dex URL is empty")
	}

	dexURL, err := url.Parse(dexURLStr)
	if err != nil {
		log.Fatalf("Failed to parse DEX URL: %v", err)
	}

	// Load the private key
	privateKeyHex := os.Getenv("PRIVATE_KEY")
	var privateKey *ecdsa.PrivateKey

	if privateKeyHex != "" {
		// Remove "0x" prefix if present
		if len(privateKeyHex) > 2 && privateKeyHex[:2] == "0x" {
			privateKeyHex = privateKeyHex[2:]
		}

		privateKey, err = crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			log.Fatalf("Failed to parse private key from hex: %v", err)
		}
	} else {
		log.Fatalf("Empty private key")
	}

	// Get the developer license from environment variable
	devLicense := os.Getenv("DEV_LICENSE")
	if devLicense == "" {
		log.Fatalf("DEV_LICENSE environment variable is required")
	}

	// Create an HTTP client with timeout and debug transport
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		// Transport: &debugTransport{
		// 	Transport: http.DefaultTransport,
		// },
	}

	// Create the DEX client
	client, err := dex.NewClient(dexURL, privateKey, httpClient)
	if err != nil {
		log.Fatalf("Failed to create DEX client: %v", err)
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Call GetToken
	token, err := client.GetToken(ctx, devLicense)
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}

	fmt.Printf("Successfully obtained token: %s\n", token)

	return token
}

func postTokenExchange(jwt string) (string, error) {
	// API endpoint
	apiURL := "https://token-exchange-api.dev.dimo.zone/v1/tokens/exchange"

	// Request payload
	requestBody := map[string]any{
		"audience":           []string{"string"},
		"nftContractAddress": "0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8",
		"privileges":         []int{1, 2, 3, 4},
		"tokenId":            978,
	}

	// Convert payload to JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Create request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("accept", "application/json")

	req.Header.Set("Authorization", "Bearer "+jwt)

	// Create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get token
	var response struct {
		Token string `json:"token"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	return response.Token, nil
}

func uploadSACDAgreement(jsonFilePath string) (string, error) {
	// Parse IPFS URL
	ipfsURL, err := url.Parse("https://assets.dimo.org/ipfs")
	if err != nil {
		return "", fmt.Errorf("failed to parse IPFS URL: %v", err)
	}

	// Load permission JSON file
	jsonData, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read permission file: %v", err)
	}

	var record models.PermissionRecord
	if err := json.Unmarshal(jsonData, &record); err != nil {
		return "", fmt.Errorf("invalid permission JSON format: %v", err)
	}

	// Verify it's a DIMO SACD document
	if record.Type != "dimo.sacd" {
		return "", fmt.Errorf("invalid document type: expected 'dimo.sacd', got '%s'", record.Type)
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &debugTransport{
			Transport: http.DefaultTransport,
		},
	}

	// Create request
	req, err := http.NewRequest("POST", ipfsURL.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IPFS upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get IPFS CID
	var response struct {
		CID string `json:"cid"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		// If the response format is different, try to extract the CID from the raw response
		// Some IPFS APIs just return the CID as plain text
		cid := strings.TrimSpace(string(body))
		fmt.Printf("Successfully uploaded to IPFS. CID: %s\n", cid)
		return cid, nil
	}

	fmt.Printf("Successfully uploaded to IPFS. CID: %s\n", response.CID)
	return response.CID, nil
}

// debugTransport is an http.RoundTripper that logs requests and responses
type debugTransport struct {
	Transport http.RoundTripper
}

func (d *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Log request
	fmt.Printf("---> %s %s\n", req.Method, req.URL)
	fmt.Printf("     Headers: %v\n", req.Header)

	// Execute request
	resp, err := d.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Log response
	fmt.Printf("<--- %d %s\n", resp.StatusCode, resp.Status)
	fmt.Printf("     Headers: %v\n", resp.Header)

	return resp, err
}

func fetchFromIPFS(cid string) ([]byte, error) {
	cid = strings.TrimPrefix(cid, "ipfs://")

	ipfsBaseURL, _ := url.Parse("https://assets.dimo.xyz/ipfs")

	// URL encode the CID to handle special characters
	// But first check if it's already URL encoded (contains %)
	if strings.Contains(cid, "%") {
		// If it contains %, it might already be URL encoded
		// Try to decode it first to avoid double encoding
		decoded, err := url.QueryUnescape(cid)
		if err == nil {
			cid = decoded
		}
	}

	ipfsURL := ipfsBaseURL.JoinPath(cid).String()
	// fmt.Println(cid)
	// fmt.Println(ipfsBaseURL.JoinPath(cid))
	// fmt.Print(ipfsURL)

	// ipfsURL = fmt.Sprintf("%s/%s", ipfsBaseURL.String(), cid)

	req, err := http.NewRequest("GET", ipfsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read IPFS response: %w", err)
	}

	return body, nil
}

func evaluateSacdDoc(record *models.PermissionRecord, privileges []int64, grantee *common.Address) (bool, error) {
	now := time.Now()
	if now.Before(record.Data.EffectiveAt) || now.After(record.Data.ExpiresAt) {
		return false, fmt.Errorf("permission record is expired or not yet effective")
	}

	if record.Data.Grantee.Address != grantee.Hex() {
		return false, fmt.Errorf("grantee address in permission record doesn't match requester")
	}

	fmt.Printf("%v\n", record.Data.Agreements[0].Permissions)
	fmt.Print("\n")

	// Aggregates all the permissions the user has.
	userPermissions := make(map[string]bool)
	for _, agreement := range record.Data.Agreements {
		fmt.Print(agreement)
		fmt.Print("\nEnd agreement\n\n")
		// Skip non permission types
		if agreement.Type != "permission" {
			continue
		}

		// // Validate the asset DID if it exists in the record
		// valid, err := t.validateAssetDID(agreement.Asset, pr)
		// if err != nil || !valid {
		// 	continue
		// }

		fmt.Print(agreement.Permissions)
		fmt.Print("\nEnd permissions\n\n")

		// Add permissions from this agreement
		for _, permission := range agreement.Permissions {
			userPermissions[permission.Name] = true
		}
	}

	fmt.Printf("Here %v\n", userPermissions)

	// Check if all requested privileges are present in the permissions
	var missingPermissions []int64

	for _, privID := range privileges {
		// Look up the permission name for this privilege ID
		permName, exists := PermissionMap[int(privID)]
		if !exists {
			// If we don't have a mapping for this privilege ID, consider it missing
			missingPermissions = append(missingPermissions, privID)
			continue
		}

		// Check if the user has this permission
		if !userPermissions[permName] {
			missingPermissions = append(missingPermissions, privID)
		}
	}

	// If any permissions are missing, return an error
	if len(missingPermissions) > 0 {
		return false, fmt.Errorf("%s", fmt.Sprintf("address %s lacks permissions %v.", grantee.Hex(), missingPermissions))
	}

	// If we get here, all permissions are valid
	return true, nil
}

func signDocument(settingsStr, jsonFilePath string, logger *zerolog.Logger) models.SACD {
	settings, err := settings.LoadConfig[config.Settings](settingsStr)
	if err != nil {
		logger.Fatal().Err(err).Msg("could not load settings")
	}

	jsonData, err := os.ReadFile(jsonFilePath)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to read permission file")
	}

	var record models.SACD
	if err := json.Unmarshal(jsonData, &record); err != nil {
		logger.Fatal().Err(err).Msg("invalid permission JSON format")
	}

	privateKeyBytes, err := hexutil.Decode(settings.TestingPK)
	if err != nil {
		log.Fatalf("Error decoding private key: %v", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}

	data, _ := json.Marshal(record.Data)
	allData := append([]byte("\x19Ethereum Signed Message\n"+fmt.Sprintf("%d", len(data))), data...)
	msgHash := crypto.Keccak256(allData)

	signature, err := crypto.Sign(msgHash, privateKey)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to sign")
	}

	signature[64] += 27

	record.Signature = "0x" + common.Bytes2Hex(signature)
	// body, err := json.Marshal(record)
	// if err != nil {
	// 	logger.Fatal().Err(err).Msg("failed to marshal record")
	// }

	return record

}

func uploadSigned(agreement models.SACD) (string, error) {
	// Parse IPFS URL
	ipfsURL, err := url.Parse("https://assets.dimo.org/ipfs")
	if err != nil {
		return "", fmt.Errorf("failed to parse IPFS URL: %v", err)
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &debugTransport{
			Transport: http.DefaultTransport,
		},
	}

	reqBody, err := json.Marshal(agreement)
	if err != nil {
		panic(err)
	}

	// Create request
	req, err := http.NewRequest("POST", ipfsURL.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IPFS upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get IPFS CID
	var response struct {
		CID string `json:"cid"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		// If the response format is different, try to extract the CID from the raw response
		// Some IPFS APIs just return the CID as plain text
		cid := strings.TrimSpace(string(body))
		fmt.Printf("Successfully uploaded to IPFS. CID: %s\n", cid)
		return cid, nil
	}

	fmt.Printf("Successfully uploaded to IPFS. CID: %s\n", response.CID)
	return response.CID, nil
}
