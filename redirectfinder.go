package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rix4uni/redirectfinder/banner"
	"github.com/spf13/pflag"
)

// ANSI color codes
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

func main() {
	// Parse command-line flags
	var payloadArg string
	var timeout int
	var concurrent int
	var vulnOnly bool
	var silent bool
	var version bool
	var noColor bool
	var verbose bool
	var redirectDomain string

	pflag.StringVarP(&payloadArg, "payload", "p", "", "Payload(s) to use: single (\"https://bing.com\"), comma-separated (\"https://bing.com, //bing.com\"), or file path (payloads.txt)")
	pflag.StringVar(&redirectDomain, "redirect", "bing.com", "Domain to check for in Location header (default: bing.com)")
	pflag.IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
	pflag.IntVar(&concurrent, "concurrent", 50, "Number of concurrent URL scans")
	pflag.BoolVar(&vulnOnly, "vuln", false, "Show only VULNERABLE URLs")
	pflag.BoolVar(&silent, "silent", false, "Silent mode")
	pflag.BoolVar(&version, "version", false, "Print the version of the tool and exit")
	pflag.BoolVar(&noColor, "nc", false, "Disable colored output")
	pflag.BoolVar(&verbose, "verbose", false, "Show verbose output (download messages, etc.)")
	pflag.Parse()

	if version {
		banner.PrintBanner()
		banner.PrintVersion()
		os.Exit(0)
	}

	if !silent {
		banner.PrintBanner()
	}

	// Parse payloads from argument or use default file
	payloads, err := parsePayloads(payloadArg, verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing payloads: %v\n", err)
		os.Exit(1)
	}

	if len(payloads) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no payloads to test\n")
		os.Exit(1)
	}

	// Replace bing.com with the specified redirect domain in all payloads
	if redirectDomain != "bing.com" {
		payloads = replaceDomainInPayloads(payloads, "bing.com", redirectDomain)
	}

	// Filter URLs using the command pipeline: urldedupe -s | grep -aE '=|%3D' | egrep -aiv '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)'
	urls, err := filterURLsWithPipeline()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error filtering URLs: %v\n", err)
		os.Exit(1)
	}

	if len(urls) == 0 {
		return
	}

	// Process URLs concurrently
	processURLsConcurrently(urls, payloads, redirectDomain, timeout, concurrent, vulnOnly, noColor)
}

func getHomeDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return usr.HomeDir, nil
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := getHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(homeDir, path[2:])
	}
	return path
}

func replaceDomainInPayloads(payloads []string, oldDomain string, newDomain string) []string {
	var replacedPayloads []string
	// Use regex for case-insensitive replacement while preserving case of the rest of the payload
	re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(oldDomain))
	for _, payload := range payloads {
		// Replace all occurrences of oldDomain with newDomain (case-insensitive)
		replaced := re.ReplaceAllString(payload, newDomain)
		replacedPayloads = append(replacedPayloads, replaced)
	}
	return replacedPayloads
}

func parsePayloads(payloadArg string, verbose bool) ([]string, error) {
	// If no payload argument provided, use default file
	if payloadArg == "" {
		homeDir, err := getHomeDir()
		if err != nil {
			return nil, fmt.Errorf("error getting home directory: %w", err)
		}
		payloadsFile := filepath.Join(homeDir, ".config", "redirectfinder", "payloads.txt")
		payloadsFile = expandPath(payloadsFile)

		// Check if payloads file exists, if not download it
		if _, err := os.Stat(payloadsFile); os.IsNotExist(err) {
			if verbose {
				fmt.Fprintf(os.Stderr, "Payloads file not found. Downloading default payloads...\n")
			}
			if err := downloadPayloads(payloadsFile); err != nil {
				return nil, fmt.Errorf("error downloading payloads: %w", err)
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "Payloads downloaded successfully to %s\n", payloadsFile)
			}
		}

		// Load payloads from file
		return loadPayloads(payloadsFile)
	}

	// First, check if it's a valid file path
	expandedPath := expandPath(payloadArg)
	if _, err := os.Stat(expandedPath); err == nil {
		// File exists, load from file
		return loadPayloads(expandedPath)
	}

	// Not a file, parse as comma-separated payloads
	// Split by comma
	payloads := strings.Split(payloadArg, ",")

	// Trim whitespace from each payload
	var result []string
	for _, p := range payloads {
		p = strings.TrimSpace(p)
		// Remove quotes if present
		p = strings.Trim(p, "\"'")
		if p != "" {
			result = append(result, p)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid payloads found in argument")
	}

	return result, nil
}

func downloadPayloads(targetPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Download the file
	url := "https://raw.githubusercontent.com/rix4uni/WordList/refs/heads/main/payloads/redirect/redirect-medium.txt"
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download payloads: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download payloads: status code %d", resp.StatusCode)
	}

	// Create the file
	out, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func filterURLsWithPipeline() ([]string, error) {
	// Execute the command pipeline: urldedupe -s | grep -aE '=|%3D' | egrep -aiv '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)'
	cmd := exec.Command("sh", "-c", "urldedupe -s | grep -aE '=|%3D' | egrep -aiv '\\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)'")

	// Set stdin to the current process stdin
	cmd.Stdin = os.Stdin

	// Capture stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Set stderr to current process stderr
	cmd.Stderr = os.Stderr

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Read filtered URLs from stdout
	var urls []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		urlStr := strings.TrimSpace(scanner.Text())
		if urlStr != "" {
			urls = append(urls, urlStr)
		}
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		// Check if it's a non-zero exit (which grep/egrep might return if no matches)
		if exitError, ok := err.(*exec.ExitError); ok {
			// Exit code 1 from grep/egrep means no matches, which is okay
			if exitError.ExitCode() != 1 {
				return nil, fmt.Errorf("command failed: %w", err)
			}
		} else {
			return nil, fmt.Errorf("command failed: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading filtered URLs: %w", err)
	}

	return urls, nil
}

func loadPayloads(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		payload := strings.TrimSpace(scanner.Text())
		if payload != "" {
			payloads = append(payloads, payload)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return payloads, nil
}

func processURLsConcurrently(urls []string, payloads []string, redirectDomain string, timeout int, concurrent int, vulnOnly bool, noColor bool) {
	// Create a channel for URLs
	urlChan := make(chan string, len(urls))

	// Create a WaitGroup to wait for all goroutines
	var wg sync.WaitGroup

	// Mutex for thread-safe output
	var outputMutex sync.Mutex

	// Start worker goroutines
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for urlStr := range urlChan {
				testURL(urlStr, payloads, redirectDomain, time.Duration(timeout)*time.Second, vulnOnly, noColor, &outputMutex)
			}
		}()
	}

	// Send URLs to channel
	for _, urlStr := range urls {
		urlChan <- urlStr
	}
	close(urlChan)

	// Wait for all goroutines to complete
	wg.Wait()
}

func formatVulnerable(noColor bool, url string) string {
	if noColor {
		return fmt.Sprintf("VULNERABLE: %s", url)
	}
	return fmt.Sprintf("%sVULNERABLE: %s %s", colorRed, url, colorReset)
}

func formatNotVulnerable(noColor bool, url string) string {
	if noColor {
		return fmt.Sprintf("NOT VULNERABLE: %s", url)
	}
	return fmt.Sprintf("%sNOT VULNERABLE: %s %s", colorGreen, url, colorReset)
}

func testURL(urlStr string, payloads []string, redirectDomain string, timeout time.Duration, vulnOnly bool, noColor bool, outputMutex *sync.Mutex) {
	// Create HTTP client with configurable timeout and disable redirect following
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test each payload
	// Match both = and %3D (URL-encoded =) followed by parameter values
	reValue := regexp.MustCompile(`(?:=|%3D)[^&\s]*`)

	for _, payload := range payloads {
		// Replace all parameter values with the payload using regex
		// Use a function to preserve the original separator (= or %3D)
		modifiedURL := reValue.ReplaceAllStringFunc(urlStr, func(match string) string {
			// Check if the match starts with %3D or =
			if strings.HasPrefix(match, "%3D") {
				return "%3D" + payload
			}
			return "=" + payload
		})

		// Make HTTP GET request
		resp, err := client.Get(modifiedURL)
		if err != nil {
			// Skip on error, but still show NOT VULNERABLE if vulnOnly is false
			if !vulnOnly {
				outputMutex.Lock()
				fmt.Println(formatNotVulnerable(noColor, modifiedURL))
				outputMutex.Unlock()
			}
			continue
		}

		// Check if response status code is 3xx (redirect)
		isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400

		// Get Location header
		location := resp.Header.Get("Location")
		
		// Parse the Location URL and check if host matches the redirect domain
		parsedURL, err := url.Parse(location)
		if err != nil {
			// If URL parsing fails, fall back to NOT VULNERABLE
			if !vulnOnly {
				outputMutex.Lock()
				fmt.Println(formatNotVulnerable(noColor, modifiedURL))
				outputMutex.Unlock()
			}
			resp.Body.Close()
			continue
		}
		
		// Check if the host matches or ends with the redirect domain
		host := strings.ToLower(parsedURL.Host)
		redirectDomainLower := strings.ToLower(redirectDomain)
		
		// Match if host equals domain or ends with .domain
		hasRedirectDomain := host == redirectDomainLower || 
			strings.HasSuffix(host, "."+redirectDomainLower)

		// Close response body
		resp.Body.Close()

		// Check if both conditions are true: 3xx status and Location contains specified domain
		if isRedirect && hasRedirectDomain {
			outputMutex.Lock()
			fmt.Println(formatVulnerable(noColor, modifiedURL))
			outputMutex.Unlock()
			return // Found vulnerability, stop testing this URL
		} else {
			// No vulnerability found, show NOT VULNERABLE if vulnOnly is false
			if !vulnOnly {
				outputMutex.Lock()
				fmt.Println(formatNotVulnerable(noColor, modifiedURL))
				outputMutex.Unlock()
			}
		}
	}
}
