package caddywaf

import "testing"

func TestPercentDecodeOnce(t *testing.T) {
	cases := []struct {
		in   string
		plus bool
		want string
	}{
		{"%75nion", true, "union"},
		{"union%20select", true, "union select"},
		{"a+b", true, "a b"},
		{"a+b", false, "a+b"},
		{"%2575", true, "%75"},           // double-encoded: single pass only
		{"%zz", true, "%zz"},             // malformed: literal
		{"trailing%", true, "trailing%"}, // lone %: literal
		{"end%2", true, "end%2"},         // truncated: literal
		{"%41%42%43", true, "ABC"},       // consecutive
		{"nothing", true, "nothing"},
		{"%00", true, "\x00"}, // null revealed
		{"", true, ""},
	}
	for _, c := range cases {
		got := percentDecodeOnce(c.in, c.plus)
		if got != c.want {
			t.Errorf("percentDecodeOnce(%q, %v) = %q, want %q", c.in, c.plus, got, c.want)
		}
	}
}

func TestOtherTransforms(t *testing.T) {
	if got := removeNulls("un\x00ion"); got != "union" {
		t.Errorf("removeNulls: %q", got)
	}
	if got := compressWhitespace("union\t\n  select"); got != "union select" {
		t.Errorf("compressWhitespace: %q", got)
	}
	if got := replaceComments("un/**/ion/*x*/sel"); got != "un ion sel" {
		t.Errorf("replaceComments: %q", got)
	}
	if got := replaceComments("un/*unterminated"); got != "un " {
		t.Errorf("replaceComments unterminated: %q", got)
	}
	if got := htmlEntityDecodeOnce("&lt;script&gt;&#39;"); got != "<script>'" {
		t.Errorf("htmlEntityDecode: %q", got)
	}
}
