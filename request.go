package caddywaf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// RequestValueExtractor struct
type RequestValueExtractor struct {
	logger              *zap.Logger
	redactSensitiveData bool // Add this field
	maxBodySize         int64
}

// Extraction Target Constants - Improved Readability and Maintainability
const (
	TargetMethod                = "METHOD"
	TargetRemoteIP              = "REMOTE_IP"
	TargetProtocol              = "PROTOCOL"
	TargetHost                  = "HOST"
	TargetArgs                  = "ARGS"
	TargetUserAgent             = "USER_AGENT"
	TargetPath                  = "PATH"
	TargetURI                   = "URI"
	TargetBody                  = "BODY"
	TargetHeaders               = "HEADERS"          // Full request headers
	TargetResponseHeaders       = "RESPONSE_HEADERS" // Full response headers
	TargetResponseBody          = "RESPONSE_BODY"    // Full response body
	TargetFileName              = "FILE_NAME"
	TargetFileMIMEType          = "FILE_MIME_TYPE"
	TargetCookies               = "COOKIES" // All cookies
	TargetURLParamPrefix        = "URL_PARAM:"
	TargetJSONPathPrefix        = "JSON_PATH:"
	TargetContentType           = "CONTENT_TYPE"
	TargetURL                   = "URL"
	TargetCookiesPrefix         = "COOKIES:"          // Dynamic cookie extraction prefix
	TargetHeadersPrefix         = "HEADERS:"          // Dynamic header extraction prefix
	TargetResponseHeadersPrefix = "RESPONSE_HEADERS:" // Dynamic response header extraction prefix
)

var sensitiveTargets = []string{"password", "token", "apikey", "authorization", "secret"} // Define sensitive targets for redaction as package variable

// NewRequestValueExtractor creates a new RequestValueExtractor with a given logger
func NewRequestValueExtractor(logger *zap.Logger, redactSensitiveData bool, maxBodySize int64) *RequestValueExtractor {
	if maxBodySize <= 0 {
		maxBodySize = 10 * 1024 * 1024 // Default 10MB
	}
	return &RequestValueExtractor{logger: logger, redactSensitiveData: redactSensitiveData, maxBodySize: maxBodySize}
}

// ExtractValue extracts values based on the target, handling comma separated targets
func (rve *RequestValueExtractor) ExtractValue(target string, r *http.Request, w http.ResponseWriter) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty extraction target")
	}
	// If target is a comma separated list, extract values and return them separated by commas.
	if strings.Contains(target, ",") {
		var values []string
		targets := strings.Split(target, ",")
		for _, t := range targets {
			t = strings.TrimSpace(t)
			v, err := rve.extractSingleValue(t, r, w)
			if err == nil {
				values = append(values, v)
			} else {
				rve.logger.Debug("Failed to extract single value from multiple targets.", zap.String("target", t), zap.Error(err))
				// if one extraction fails we continue and don't return an error.
			}
		}
		return strings.Join(values, ","), nil // Returning concatenated values
	}
	return rve.extractSingleValue(target, r, w)
}

// extractSingleValue extracts a value based on a single target
func (rve *RequestValueExtractor) extractSingleValue(target string, r *http.Request, w http.ResponseWriter) (string, error) {
	origTarget := target
	targetUpper := strings.ToUpper(strings.TrimSpace(target))
	var unredactedValue string
	var err error

	// Optimization: Use a map for target extraction logic
	extractionLogic := map[string]func() (string, error){
		TargetMethod:   func() (string, error) { return r.Method, nil },
		TargetRemoteIP: func() (string, error) { return r.RemoteAddr, nil },
		TargetProtocol: func() (string, error) { return r.Proto, nil },
		TargetHost:     func() (string, error) { return r.Host, nil },
		TargetArgs: func() (string, error) {
			return r.URL.RawQuery, rve.checkEmpty(r.URL.RawQuery, target, "Query string is empty")
		},
		TargetUserAgent: func() (string, error) {
			value := r.UserAgent()
			rve.logIfEmpty(value, target, "User-Agent is empty")
			return value, nil
		},
		TargetPath: func() (string, error) {
			value := r.URL.Path
			rve.logIfEmpty(value, target, "Request path is empty")
			return value, nil
		},
		TargetURI: func() (string, error) {
			value := r.URL.RequestURI()
			rve.logIfEmpty(value, target, "Request URI is empty")
			return value, nil
		},
		TargetBody:            func() (string, error) { return rve.extractBody(r, target) },                                     // Separate body extraction
		TargetHeaders:         func() (string, error) { return rve.extractAllHeaders(r.Header, "Request headers", target) },     // Helper for headers
		TargetResponseHeaders: func() (string, error) { return rve.extractAllHeaders(w.Header(), "Response headers", target) },  // Helper for response headers
		TargetResponseBody:    func() (string, error) { return rve.extractResponseBody(w, target) },                             // Helper for response body
		TargetFileName:        func() (string, error) { return rve.extractFileName(r, target) },                                 // Helper for filename
		TargetFileMIMEType:    func() (string, error) { return rve.extractFileMIMEType(r, target) },                             // Helper for mime type
		TargetCookies:         func() (string, error) { return rve.extractAllCookies(r.Cookies(), "No cookies found", target) }, // Helper for cookies
		TargetContentType: func() (string, error) {
			return r.Header.Get("Content-Type"), rve.checkEmpty(r.Header.Get("Content-Type"), target, "Content-Type header not found")
		},
		TargetURL: func() (string, error) {
			return r.URL.String(), rve.checkEmpty(r.URL.String(), target, "URL could not be extracted")
		},
	}

	if extractor, exists := extractionLogic[targetUpper]; exists {
		unredactedValue, err = extractor()
		if err != nil {
			return "", err // Return error from extractor
		}
	} else if strings.HasPrefix(target, TargetHeadersPrefix) {
		unredactedValue, err = rve.extractDynamicHeader(r.Header, strings.TrimPrefix(target, TargetHeadersPrefix), target)
		if err != nil {
			return "", err
		}
	} else if strings.HasPrefix(target, TargetResponseHeadersPrefix) {
		unredactedValue, err = rve.extractDynamicResponseHeader(w.Header(), strings.TrimPrefix(target, TargetResponseHeadersPrefix), target)
		if err != nil {
			return "", err
		}
	} else if strings.HasPrefix(target, TargetCookiesPrefix) {
		unredactedValue, err = rve.extractDynamicCookie(r, strings.TrimPrefix(target, TargetCookiesPrefix), target)
		if err != nil {
			return "", err
		}
	} else if target == TargetCookies {
		unredactedValue, err = rve.extractAllCookies(r.Cookies(), "No cookies found", target)
		if err != nil {
			return "", err
		}
	} else if strings.HasPrefix(targetUpper, TargetURLParamPrefix) {
		// CRITICAL FIX: Use the original parameter name (without uppercase conversion)
		paramName := strings.TrimPrefix(origTarget, TargetURLParamPrefix)
		unredactedValue, err = rve.extractURLParam(r.URL, paramName, target)
		if err != nil {
			return "", err
		}
	} else if strings.HasPrefix(targetUpper, TargetJSONPathPrefix) {
		jsonPath := strings.TrimPrefix(origTarget, TargetJSONPathPrefix)
		unredactedValue, err = rve.extractValueForJSONPath(r, jsonPath, target)
		if err != nil {
			return "", err
		}
	} else {
		rve.logger.Warn("Unknown extraction target", zap.String("target", target))
		return "", fmt.Errorf("unknown extraction target: %s", target)
	}

	// Redact sensitive fields before returning the value (as before)
	value := rve.RedactValueIfSensitive(target, unredactedValue)

	// Log the extracted value (redacted if necessary)
	rve.logger.Debug("Extracted value",
		zap.String("target", target),
		zap.String("value", value), // Log the potentially redacted value
	)

	// Return the unredacted value for rule matching
	return unredactedValue, nil
}

// Helper function to check for empty value and log debug message if empty
func (rve *RequestValueExtractor) checkEmpty(value string, target, message string) error {
	if value == "" {
		rve.logger.Debug(message, zap.String("target", target))
		return fmt.Errorf("%s for target: %s", message, target)
	}
	return nil
}

// Helper function to log debug message if value is empty
func (rve *RequestValueExtractor) logIfEmpty(value string, target string, message string) {
	if value == "" {
		rve.logger.Debug(message, zap.String("target", target))
	}
}

// Helper function to extract body
func (rve *RequestValueExtractor) extractBody(r *http.Request, target string) (string, error) {
	if r.Body == nil {
		rve.logger.Warn("Request body is nil", zap.String("target", target))
		return "", fmt.Errorf("request body is nil for target: %s", target)
	}
	if r.ContentLength == 0 {
		rve.logger.Debug("Request body is empty", zap.String("target", target))
		return "", fmt.Errorf("request body is empty for target: %s", target)
	}
	reader := io.LimitReader(r.Body, rve.maxBodySize)
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		rve.logger.Error("Failed to read request body", zap.Error(err))
		return "", fmt.Errorf("failed to read request body for target %s: %w", target, err)
	}
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes))) // Restore body for next read
	return string(bodyBytes), nil
}

// Helper function to extract all headers
func (rve *RequestValueExtractor) extractAllHeaders(header http.Header, logMessage, target string) (string, error) {
	if len(header) == 0 {
		rve.logger.Debug(logMessage+" are empty", zap.String("target", target))
		return "", fmt.Errorf("%s are empty for target: %s", logMessage, target)
	}
	headers := make([]string, 0)
	for name, values := range header {
		headers = append(headers, fmt.Sprintf("%s: %s", name, strings.Join(values, ",")))
	}
	return strings.Join(headers, "; "), nil
}

// Helper function to extract response body (for phase 4)
func (rve *RequestValueExtractor) extractResponseBody(w http.ResponseWriter, target string) (string, error) {
	if w == nil {
		return "", fmt.Errorf("response body not accessible outside Phase 4 for target: %s", target)
	}
	recorder, ok := w.(*responseRecorder)
	if !ok || recorder == nil {
		return "", fmt.Errorf("response recorder not available for target: %s", target)
	}
	if recorder.body.Len() == 0 {
		rve.logger.Debug("Response body is empty", zap.String("target", target))
		return "", fmt.Errorf("response body is empty for target: %s", target)
	}
	return recorder.BodyString(), nil
}

// Helper function to extract filename from multipart form
func (rve *RequestValueExtractor) extractFileName(r *http.Request, target string) (string, error) {
	if r.MultipartForm == nil || r.MultipartForm.File == nil {
		rve.logger.Debug("Multipart form file not found", zap.String("target", target))
		return "", fmt.Errorf("multipart form file not found for target: %s", target)
	}

	for _, files := range r.MultipartForm.File {
		if len(files) > 0 { // Check if there are files
			return files[0].Filename, nil // Return the first file's name
		}
	}
	return "", fmt.Errorf("no files found in multipart form for target: %s", target) // No files found but form is present
}

// Helper function to extract MIME type from multipart form
func (rve *RequestValueExtractor) extractFileMIMEType(r *http.Request, target string) (string, error) {
	if r.MultipartForm == nil || r.MultipartForm.File == nil {
		rve.logger.Debug("Multipart form file not found", zap.String("target", target))
		return "", fmt.Errorf("multipart form file not found for target: %s", target)
	}

	for _, files := range r.MultipartForm.File {
		if len(files) > 0 { // Check if files are present
			return files[0].Header.Get("Content-Type"), nil // Return MIME type of the first file
		}
	}
	return "", fmt.Errorf("no files found in multipart form for target: %s", target) // No files found even though form is present
}

// Helper function to extract dynamic header value
func (rve *RequestValueExtractor) extractDynamicHeader(header http.Header, headerName, target string) (string, error) {
	headerValue := header.Get(headerName)
	if headerValue == "" {
		rve.logger.Debug("Header not found", zap.String("header", headerName), zap.String("target", target))
		return "", fmt.Errorf("header '%s' not found for target: %s", headerName, target)
	}
	return headerValue, nil
}

// Helper function to extract dynamic response header value (for phase 3)
func (rve *RequestValueExtractor) extractDynamicResponseHeader(header http.Header, headerName, target string) (string, error) {
	if header == nil {
		return "", fmt.Errorf("response headers not available during this phase for target: %s", target)
	}
	headerValue := header.Get(headerName)
	if headerValue == "" {
		rve.logger.Debug("Response header not found", zap.String("header", headerName), zap.String("target", target))
		return "", fmt.Errorf("response header '%s' not found for target: %s", headerName, target)
	}
	return headerValue, nil
}

// Helper function to extract dynamic cookie value
func (rve *RequestValueExtractor) extractDynamicCookie(r *http.Request, cookieName string, target string) (string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		rve.logger.Debug("Cookie not found", zap.String("cookie", cookieName), zap.String("target", target))
		return "", fmt.Errorf("cookie '%s' not found for target: %s", cookieName, target)
	}
	return cookie.Value, nil
}

// Helper function to extract URL parameter value
func (rve *RequestValueExtractor) extractURLParam(url *url.URL, paramName string, target string) (string, error) {
	// Clean up the paramName by removing any potential remaining prefix
	// This is critical for handling cases where the origTarget trimming didn't fully work
	cleanParamName := strings.TrimPrefix(paramName, "url_param:")

	paramValue := url.Query().Get(cleanParamName)
	if paramValue == "" {
		rve.logger.Debug("URL parameter not found",
			zap.String("parameter", paramName),
			zap.String("clean_parameter", cleanParamName),
			zap.String("target", target),
			zap.String("available_params", url.RawQuery)) // Log available params for debugging
		return "", fmt.Errorf("url parameter '%s' not found for target: %s", paramName, target)
	}
	return paramValue, nil
}

// Helper function to extract value for JSON Path
func (rve *RequestValueExtractor) extractValueForJSONPath(r *http.Request, jsonPath string, target string) (string, error) {
	if r.Body == nil {
		rve.logger.Warn("Request body is nil", zap.String("target", target))
		return "", fmt.Errorf("request body is nil for target: %s", target)
	}
	if r.ContentLength == 0 {
		rve.logger.Debug("Request body is empty", zap.String("target", target))
		return "", fmt.Errorf("request body is empty for target: %s", target)
	}

	reader := io.LimitReader(r.Body, rve.maxBodySize)
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		rve.logger.Error("Failed to read request body", zap.Error(err))
		return "", fmt.Errorf("failed to read request body for JSON_PATH target %s: %w", target, err)
	}
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes))) // Restore body for next read

	// Use helper method to dynamically extract value based on JSON path (e.g., 'data.items.0.name').
	unredactedValue, err := rve.extractJSONPath(string(bodyBytes), jsonPath)
	if err != nil {
		rve.logger.Debug("Failed to extract value from JSON path", zap.String("target", target), zap.String("path", jsonPath), zap.Error(err))
		return "", fmt.Errorf("failed to extract from JSON path '%s': %w", jsonPath, err)
	}
	return unredactedValue, nil
}

// Helper function to redact value if target is sensitive
func (rve *RequestValueExtractor) RedactValueIfSensitive(target string, value string) string {
	if rve.redactSensitiveData {
		for _, sensitive := range sensitiveTargets {
			if strings.Contains(strings.ToLower(target), sensitive) {
				return "REDACTED"
			}
		}
	}
	return value
}

// Helper function to extract all cookies
func (rve *RequestValueExtractor) extractAllCookies(cookies []*http.Cookie, logMessage string, target string) (string, error) {
	if len(cookies) == 0 {
		rve.logger.Debug(logMessage, zap.String("target", target))
		return "", fmt.Errorf("%s for target: %s", logMessage, target)
	}
	cookieStrings := make([]string, 0)
	for _, cookie := range cookies {
		cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
	}
	return strings.Join(cookieStrings, "; "), nil
}

// Helper function for JSON path extraction
func (rve *RequestValueExtractor) extractJSONPath(jsonStr string, jsonPath string) (string, error) {
	// Validate input JSON string
	if jsonStr == "" {
		return "", fmt.Errorf("json string is empty")
	}
	// Validate JSON path
	if jsonPath == "" {
		return "", fmt.Errorf("json path is empty")
	}

	// Unmarshal JSON string into an interface{}
	var jsonData interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonData); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	// Check if JSON data is valid
	if jsonData == nil {
		return "", fmt.Errorf("invalid json data")
	}

	// Split JSON path into parts (e.g., "data.items.0.name" -> ["data", "items", "0", "name"])
	pathParts := strings.Split(jsonPath, ".")
	current := jsonData

	// Traverse the JSON structure using the path parts
	for _, part := range pathParts {
		if current == nil {
			return "", fmt.Errorf("invalid json path: part '%s' not found in path '%s'", part, jsonPath)
		}

		switch value := current.(type) {
		case map[string]interface{}:
			// If the current value is a map, look for the key
			if next, ok := value[part]; ok {
				current = next
			} else {
				return "", fmt.Errorf("invalid json path: key '%s' not found in path '%s'", part, jsonPath)
			}
		case []interface{}:
			// If the current value is an array, parse the index
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(value) {
				return "", fmt.Errorf("invalid json path: index '%s' is out of bounds or invalid in path '%s'", part, jsonPath)
			}
			current = value[index]
		default:
			// If the current value is neither a map nor an array, the path is invalid
			return "", fmt.Errorf("invalid json path: unexpected type at part '%s' in path '%s'", part, jsonPath)
		}
	}

	// Check if the final value is nil
	if current == nil {
		return "", fmt.Errorf("invalid json path: value is nil at path '%s'", jsonPath)
	}

	// Convert the final value to a string
	switch v := current.(type) {
	case string:
		return v, nil
	case int, int64, float64, bool:
		return fmt.Sprintf("%v", v), nil
	default:
		// For complex types (e.g., maps, arrays), marshal them back to JSON
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON value at path '%s': %w", jsonPath, err)
		}
		return string(jsonBytes), nil
	}
}
