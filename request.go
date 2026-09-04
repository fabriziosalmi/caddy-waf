package caddywaf

import (
	"bytes"
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

var targetAliases = map[string]string{
	"REQUEST_HEADERS":  "HEADERS",
	"REQUEST_COOKIES":  "COOKIES",
	"REQUEST_URI":      "URI",
	"REQUEST_URI_RAW":  "URI",
	"QUERY_STRING":     "ARGS",
	"REQUEST_BODY":     "BODY",
	"REQUEST_FILENAME": "PATH",
	"REQUEST_METHOD":   "METHOD",
	"REMOTE_ADDR":      "REMOTE_IP",
}

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
	// Canonicalise ModSecurity/CRS target aliases so SecLang-derived rule files
	// resolve. Without this, targets like REQUEST_COOKIES fell through to
	// "unknown extraction target" and were silently skipped -- 135 bundled rules
	// lost cookie/header coverage and one was fully inert.
	if canon, ok := targetAliases[targetUpper]; ok {
		targetUpper = canon
	}
	var unredactedValue string
	var err error

	// Static dispatch on the (canonicalised, upper-cased) target. This runs once
	// per rule-target on the hot path, so it must not allocate: a previous
	// implementation built a 16-entry map of closures on every call, which was
	// the single largest source of per-request allocations (#115).
	switch targetUpper {
	case TargetMethod:
		unredactedValue = r.Method
	case TargetRemoteIP:
		// Resolved under the trusted_proxies boundary in ServeHTTP; falls back
		// to the raw peer address when not set (e.g. a direct extractor call).
		if v, ok := r.Context().Value(clientIPKey{}).(string); ok && v != "" {
			unredactedValue = v
		} else {
			unredactedValue = extractIP(r.RemoteAddr) // bare IP, consistent with the resolved value
		}
	case TargetProtocol:
		unredactedValue = r.Proto
	case TargetHost:
		unredactedValue = r.Host
	case TargetArgs:
		unredactedValue = r.URL.RawQuery
		err = rve.checkEmpty(unredactedValue, target, "Query string is empty")
	case TargetUserAgent:
		unredactedValue = r.UserAgent()
		rve.logIfEmpty(unredactedValue, target, "User-Agent is empty")
	case TargetPath:
		unredactedValue = r.URL.Path
		rve.logIfEmpty(unredactedValue, target, "Request path is empty")
	case TargetURI:
		unredactedValue = r.URL.RequestURI()
		rve.logIfEmpty(unredactedValue, target, "Request URI is empty")
	case TargetBody:
		unredactedValue, err = rve.extractBody(r, target)
	case TargetHeaders:
		unredactedValue, err = rve.extractAllHeaders(r.Header, "Request headers", target)
	case TargetResponseHeaders:
		unredactedValue, err = rve.extractResponseHeaders(w, target) // nil-safe; see issue #144
	case TargetResponseBody:
		unredactedValue, err = rve.extractResponseBody(w, target)
	case TargetFileName:
		unredactedValue, err = rve.extractFileName(r, target)
	case TargetFileMIMEType:
		unredactedValue, err = rve.extractFileMIMEType(r, target)
	case TargetCookies:
		unredactedValue, err = rve.extractAllCookies(r.Cookies(), "No cookies found", target)
	case TargetContentType:
		unredactedValue = r.Header.Get("Content-Type")
		err = rve.checkEmpty(unredactedValue, target, "Content-Type header not found")
	case TargetURL:
		unredactedValue = r.URL.String()
		err = rve.checkEmpty(unredactedValue, target, "URL could not be extracted")
	default:
		switch {
		case strings.HasPrefix(target, TargetHeadersPrefix):
			unredactedValue, err = rve.extractDynamicHeader(r.Header, strings.TrimPrefix(target, TargetHeadersPrefix), target)
		case strings.HasPrefix(target, TargetResponseHeadersPrefix):
			if w == nil {
				return "", fmt.Errorf("response headers not accessible outside Phase 3/4 for target: %s", target)
			}
			unredactedValue, err = rve.extractDynamicResponseHeader(w.Header(), strings.TrimPrefix(target, TargetResponseHeadersPrefix), target)
		case strings.HasPrefix(target, TargetCookiesPrefix):
			unredactedValue, err = rve.extractDynamicCookie(r, strings.TrimPrefix(target, TargetCookiesPrefix), target)
		case strings.HasPrefix(targetUpper, TargetURLParamPrefix):
			// Use the original parameter name (without uppercase conversion).
			unredactedValue, err = rve.extractURLParam(r.URL, strings.TrimPrefix(origTarget, TargetURLParamPrefix), target)
		case strings.HasPrefix(targetUpper, TargetJSONPathPrefix):
			unredactedValue, err = rve.extractValueForJSONPath(r, strings.TrimPrefix(origTarget, TargetJSONPathPrefix), target)
		default:
			rve.logger.Warn("Unknown extraction target", zap.String("target", target))
			return "", fmt.Errorf("unknown extraction target: %s", target)
		}
	}
	if err != nil {
		return "", err
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
// bodyBufferKey carries the buffered request body (the inspection window) in the
// request context. ServeHTTP captures the body once via captureRequestBody, so
// extraction reads it here without draining r.Body -- the body the upstream
// still needs.
type bodyBufferKey struct{}

// bufferRequestBody reads up to limit bytes of the request body for inspection
// and rebuilds r.Body so the full body still reaches downstream and the upstream
// proxy. It returns the inspection window (at most limit bytes).
//
// A body within the limit is made fully re-readable (bytes.Reader) with GetBody
// set, so the upstream and its retries get the exact bytes. A larger body is
// forwarded whole -- the buffered prefix followed by the un-read remainder --
// while only the prefix is inspected; GetBody is left unset because that tail is
// a one-shot stream.
//
// This replaces the previous restore, which spliced an already-consumed r.Body
// into an io.MultiReader. The reconstructed stream stopped yielding the bytes
// while r.ContentLength kept its original value, so the upstream saw
// "ContentLength=N with Body length 0", broke the connection, and every POST
// carrying a body failed with a 502.
func bufferRequestBody(r *http.Request, limit int64) ([]byte, error) {
	// Read the inspection window plus one byte, to learn whether the body
	// exceeded the window without discarding the overflow.
	buf, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) <= limit {
		bodyBytes := buf
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		return bodyBytes, nil
	}
	// Body exceeds the inspection window: forward prefix + remainder, inspect the
	// prefix only. The original body keeps streaming after the buffered bytes,
	// and its Closer is preserved.
	prefix := buf[:limit]
	original := r.Body
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), original), original}
	return prefix, nil
}

// readAndRestoreBody buffers the body against the extractor's maxBodySize. It is
// the fallback for extraction paths that were not pre-buffered by ServeHTTP
// (e.g. a direct unit test).
func (rve *RequestValueExtractor) readAndRestoreBody(r *http.Request) ([]byte, error) {
	return bufferRequestBody(r, rve.maxBodySize)
}

func (rve *RequestValueExtractor) extractBody(r *http.Request, target string) (string, error) {
	if r.Body == nil {
		rve.logger.Warn("Request body is nil", zap.String("target", target))
		return "", fmt.Errorf("request body is nil for target: %s", target)
	}
	if r.ContentLength == 0 {
		rve.logger.Debug("Request body is empty", zap.String("target", target))
		return "", fmt.Errorf("request body is empty for target: %s", target)
	}
	// ServeHTTP buffers the body up front and stashes the inspection window in
	// the context; read it there so extraction never drains the body the
	// upstream will read.
	if buf, ok := r.Context().Value(bodyBufferKey{}).([]byte); ok {
		return string(buf), nil
	}
	// Fallback (a caller that did not pre-buffer, e.g. a direct unit test):
	// consume once and restore.
	bodyBytes, err := rve.readAndRestoreBody(r)
	if err != nil {
		rve.logger.Error("Failed to read request body", zap.Error(err))
		return "", fmt.Errorf("failed to read request body for target %s: %w", target, err)
	}
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

// extractResponseHeaders returns the full response header set. Response targets
// are only populated in Phase 3/4; when a rule file places RESPONSE_HEADERS in
// an earlier phase (several OWASP CRS rules do, e.g. 950010), handlePhase passes
// a nil writer, so this must degrade to an error rather than dereference nil.
// See issue #144.
func (rve *RequestValueExtractor) extractResponseHeaders(w http.ResponseWriter, target string) (string, error) {
	if w == nil {
		return "", fmt.Errorf("response headers not accessible outside Phase 3/4 for target: %s", target)
	}
	return rve.extractAllHeaders(w.Header(), "Response headers", target)
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

	bodyBytes, ok := r.Context().Value(bodyBufferKey{}).([]byte)
	if !ok {
		var err error
		bodyBytes, err = rve.readAndRestoreBody(r)
		if err != nil {
			rve.logger.Error("Failed to read request body", zap.Error(err))
			return "", fmt.Errorf("failed to read request body for JSON_PATH target %s: %w", target, err)
		}
	}

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
