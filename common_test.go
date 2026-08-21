package caddywaf

import "net/http"

const (
	geoIPdata  = "GeoLite2-Country.mmdb"
	localIP    = "127.0.0.1:32555"
	aliCNIP    = "47.88.198.38"
	googleUSIP = "74.125.131.105"
	googleBRIP = "128.201.228.12"
	googleRUIP = "74.125.131.94"
	testURL    = "http://example.com"
)

var customResponse = map[int]CustomBlockResponse{
	403: {
		StatusCode: http.StatusForbidden,
		Body:       "Access Denied",
	},
}
