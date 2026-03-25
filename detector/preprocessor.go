package detector

import (
	"encoding/hex"
	"html"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	// Space-separated hex bytes: "47 6f 20 68 61 63 6b"
	// Require at least 4 pairs so normal hex numbers don't trigger
	hexBytesRe = regexp.MustCompile(`(?i)\b[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){3,}\b`)

	// \xNN and \uNNNN escape sequences
	escapeSeqRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})`)
)

// Preprocess returns the original input plus any decoded variants.
// Only adds a candidate if decoding actually changes the string.
// Detectors run on all candidates - the highest score wins.
func Preprocess(input string) []string {
	candidates := []string{input}
	seen := map[string]bool{input: true}

	add := func(s string) {
		if s != input && !seen[s] {
			candidates = append(candidates, s)
			seen[s] = true
		}
	}

	add(decodeHexBytes(input))
	add(decodeEscapeSequences(input))
	// stdlib handles &#NNN; and &amp; style entities
	add(html.UnescapeString(input))

	return candidates
}

// decodeHexBytes tries to decode a space-separated hex byte sequence.
// Only accepts printable ASCII output - avoids decoding binary garbage.
func decodeHexBytes(input string) string {
	match := hexBytesRe.FindString(input)
	if match == "" {
		return input
	}

	hexStr := strings.ReplaceAll(match, " ", "")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return input
	}

	// Reject if decoded bytes contain non-printable ASCII
	for _, c := range b {
		if c < 32 || c > 126 {
			return input
		}
	}

	return strings.Replace(input, match, string(b), 1)
}

// decodeEscapeSequences replaces \xNN and \uNNNN literals with their actual characters.
func decodeEscapeSequences(input string) string {
	return escapeSeqRe.ReplaceAllStringFunc(input, func(match string) string {
		if strings.HasPrefix(match, `\x`) {
			b, err := hex.DecodeString(match[2:])
			if err == nil && len(b) == 1 {
				return string(rune(b[0]))
			}
		}
		if strings.HasPrefix(match, `\u`) {
			n, err := strconv.ParseInt(match[2:], 16, 32)
			if err == nil {
				r := rune(n)
				if unicode.IsPrint(r) {
					return string(r)
				}
			}
		}
		return match
	})
}
