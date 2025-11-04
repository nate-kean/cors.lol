package main

import (
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	rateLimit         = parseInt(os.Getenv("RATE_LIMIT_REQUESTS"))
	rateLimitDuration = time.Duration(parseInt(os.Getenv("RATE_LIMIT_PER_MINUTES"))) * time.Minute
	requestCounts     = make(map[string]int)
	countsLock        = sync.Mutex{}
	// Max allowed size of the request body is 10MB
	maxBodySize int64 = 10 << 20 // 10 MB
	// HTTP client with timeouts
	client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			MaxConnsPerHost:       100,
		},
	}
)

func parseInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return i
}

func init() {
	// Register additional MIME types
	mime.AddExtensionType(".js", "application/javascript")
	mime.AddExtensionType(".css", "text/css")
	mime.AddExtensionType(".json", "application/json")
}

func main() {
	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Register handlers
	http.HandleFunc("/", limitRate(limitSize(handler)))

	// Get port
	port := "8080" // Default
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Invalid port number: %v", err)
	}

	// Start server
	log.Printf("Starting server on port %d\n", portNum)
	log.Fatal(http.ListenAndServe(":" + port, nil))
}

func prepareURL(rawURL string) (string, error) {
	// Remove any whitespace
	rawURL = strings.TrimSpace(rawURL)

	// Fix common URL issues
	if strings.HasPrefix(rawURL, "//") {
		rawURL = "https:" + rawURL
	} else if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	// Parse and validate the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	// Ensure the URL has a host
	if parsedURL.Host == "" {
		return "", fmt.Errorf("invalid URL: missing host")
	}

	return parsedURL.String(), nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Handle OPTIONS method
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get URL from query parameter.
	// Can't use url.URL.Query() because that omits the query in the requested URL.
	rawQuery := r.URL.RawQuery
	if !strings.HasPrefix(rawQuery, "url=") {
		log.Printf("Missing URL parameter in request from %s", r.RemoteAddr)
		http.Error(w, "URL parameter is required", http.StatusBadRequest)
		return
	}
	targetURL := rawQuery[4:]

	// Prepare URL
	preparedURL, err := prepareURL(targetURL)
	if err != nil {
		log.Printf("Invalid URL %q from %s: %v", targetURL, r.RemoteAddr, err)
		http.Error(w, fmt.Sprintf("Invalid URL: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("Proxying request to %q from %s", preparedURL, r.RemoteAddr)

	// Create request
	req, err := http.NewRequestWithContext(r.Context(), r.Method, preparedURL, r.Body)
	if err != nil {
		log.Printf("Failed to create request for %q: %v", preparedURL, err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy request headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch %q: %v", preparedURL, err)
		if strings.Contains(err.Error(), "no such host") {
			http.Error(w, "Invalid host", http.StatusBadGateway)
		} else if strings.Contains(err.Error(), "timeout") {
			http.Error(w, "Request timed out", http.StatusGatewayTimeout)
		} else {
			http.Error(w, "Failed to fetch URL", http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Override CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response for %q after %d bytes: %v", preparedURL, written, err)
		return
	}

	log.Printf("Successfully proxied %d bytes from %q", written, preparedURL)
}

func limitRate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		countsLock.Lock()
		count, exists := requestCounts[ip]

		if !exists {
			requestCounts[ip] = 1
			go func(ip string) {
				time.Sleep(rateLimitDuration)
				countsLock.Lock()
				delete(requestCounts, ip)
				countsLock.Unlock()
			}(ip)
		} else if count >= rateLimit {
			countsLock.Unlock()
			log.Printf("Rate limit exceeded for %s", ip)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		} else {
			requestCounts[ip]++
		}
		countsLock.Unlock()

		next(w, r)
	}
}

func limitSize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		next(w, r)
	}
}
