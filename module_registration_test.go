package caddywaf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegisterModuleArgumentIsScannable enforces the constraint imposed by the
// static analyzer behind Caddy's package registry
// (https://caddyserver.com/account/register-package).
//
// Registering a package makes the registry scan the source to discover which
// Caddy modules it registers. That scanner is deliberately simple: the argument
// to caddy.RegisterModule must be either a composite literal (Foo{}) or a call
// to new(). Anything else -- notably &Foo{}, which parses as an ast.UnaryExpr
// wrapping the literal, or a constructor call such as New() -- aborts the scan
// with the opaque portal error:
//
//	unable to scan modules in package github.com/fabriziosalmi/caddy-waf
//
// The message never names the offending line, so this test exists to catch the
// mistake here instead of during a registration attempt. See
// CADDY_MODULE_REGISTRATION.md and
// https://caddy.community/t/unable-to-register-module-in-the-portal/33572
//
// Semantically new(Middleware) and &Middleware{} are identical, so satisfying
// the scanner costs nothing.
func TestRegisterModuleArgumentIsScannable(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("globbing package files: %v", err)
	}

	fset := token.NewFileSet()
	found := 0

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		parsed, err := parser.ParseFile(fset, file, src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}

		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "RegisterModule" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "caddy" {
				return true
			}
			found++

			pos := fset.Position(call.Pos())
			if len(call.Args) != 1 {
				t.Errorf("%s: caddy.RegisterModule takes 1 argument, got %d", pos, len(call.Args))
				return true
			}

			switch arg := call.Args[0].(type) {
			case *ast.CompositeLit:
				// Foo{} -- accepted by the scanner.
			case *ast.CallExpr:
				// Only new(Foo) is accepted; any other call is a constructor
				// the scanner cannot follow.
				ident, ok := arg.Fun.(*ast.Ident)
				if !ok || ident.Name != "new" {
					t.Errorf("%s: caddy.RegisterModule argument must be a composite literal or new(); "+
						"a constructor call is not scannable by Caddy's package registry", pos)
				}
			case *ast.UnaryExpr:
				t.Errorf("%s: caddy.RegisterModule argument is &-prefixed (parses as ast.UnaryExpr). "+
					"Caddy's package registry cannot scan this and registration fails with "+
					"\"unable to scan modules in package\". Use new(Middleware) instead.", pos)
			default:
				t.Errorf("%s: caddy.RegisterModule argument must be a composite literal or new(), got %T", pos, arg)
			}
			return true
		})
	}

	if found == 0 {
		t.Fatal("no caddy.RegisterModule call found in the package; the module would not register at all")
	}
	if found != 1 {
		t.Errorf("expected exactly one caddy.RegisterModule call, found %d", found)
	}
}
