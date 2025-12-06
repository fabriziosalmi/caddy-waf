//go:build with_ui

package caddywaf

import "embed"

//go:embed ui/*
var Assets embed.FS
