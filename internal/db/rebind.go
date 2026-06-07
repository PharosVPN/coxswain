// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package db

import "strings"

// rebindPositional rewrites a query that uses SQLite/MySQL-style `?` placeholders
// into PostgreSQL's `$1, $2, ...` ordinal placeholders. It is applied at the
// driver layer (see rebindConn) so every query the data layer issues — all
// written with `?` — works unchanged on Postgres.
//
// It is literal-aware: a `?` inside a single-quoted string ('...'), a
// double-quoted identifier ("..."), a dollar-quoted string ($tag$...$tag$), or a
// line/block comment is NOT a placeholder and is left untouched. SQLite escapes a
// quote by doubling it (” inside a '...' string), which this scanner handles
// naturally: the closing quote simply toggles state and the next quote re-opens.
// PostgreSQL's own `$N` parameters and `$tag$` dollar-quotes are passed through
// verbatim, so a string that is already rebound (or hand-written for PG) is a
// no-op.
//
// The data layer uses only `?` placeholders and never `$N`, so the only `$`
// sequences reaching here in real queries are inside string literals — but the
// dollar-quote handling keeps the rewrite correct even if that changes.
func rebindPositional(query string) string {
	// Fast path: nothing to do when there is no '?' at all. (Comments/strings
	// containing '?' are rare in this codebase, so the scan below is only paid
	// when a '?' is actually present.)
	if !strings.ContainsRune(query, '?') {
		return query
	}

	var b strings.Builder
	b.Grow(len(query) + 8)

	n := 0 // placeholder ordinal
	i := 0
	for i < len(query) {
		c := query[i]
		switch c {
		case '\'', '"':
			// Single-quoted string literal or double-quoted identifier. Copy
			// through to the matching close quote, treating a doubled quote
			// ('' or "") as an escaped quote that stays inside the literal.
			quote := c
			b.WriteByte(c)
			i++
			for i < len(query) {
				if query[i] == quote {
					// A doubled quote is an escaped quote within the literal.
					if i+1 < len(query) && query[i+1] == quote {
						b.WriteByte(quote)
						b.WriteByte(quote)
						i += 2
						continue
					}
					b.WriteByte(quote)
					i++
					break
				}
				b.WriteByte(query[i])
				i++
			}
		case '$':
			// A dollar-quoted string ($tag$...$tag$) or a `$N` parameter that is
			// already in PG form. Detect a dollar-quote opener: $ followed by an
			// optional tag of letters/digits/underscore, then another $.
			if tag, ok := dollarTag(query[i:]); ok {
				b.WriteString(tag)
				i += len(tag)
				// Copy through until the matching closing tag.
				if idx := strings.Index(query[i:], tag); idx >= 0 {
					b.WriteString(query[i : i+idx+len(tag)])
					i += idx + len(tag)
				} else {
					// Unterminated dollar-quote: copy the rest verbatim.
					b.WriteString(query[i:])
					i = len(query)
				}
			} else {
				b.WriteByte(c)
				i++
			}
		case '-':
			// Line comment: -- ... to end of line.
			if i+1 < len(query) && query[i+1] == '-' {
				if idx := strings.IndexByte(query[i:], '\n'); idx >= 0 {
					b.WriteString(query[i : i+idx+1])
					i += idx + 1
				} else {
					b.WriteString(query[i:])
					i = len(query)
				}
			} else {
				b.WriteByte(c)
				i++
			}
		case '/':
			// Block comment: /* ... */.
			if i+1 < len(query) && query[i+1] == '*' {
				if idx := strings.Index(query[i+2:], "*/"); idx >= 0 {
					end := i + 2 + idx + 2
					b.WriteString(query[i:end])
					i = end
				} else {
					b.WriteString(query[i:])
					i = len(query)
				}
			} else {
				b.WriteByte(c)
				i++
			}
		case '?':
			n++
			b.WriteByte('$')
			b.WriteString(itoa(n))
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// dollarTag reports whether s begins with a PostgreSQL dollar-quote opener
// ($...$ where the inner part is an optional valid tag) and returns that opener
// (e.g. "$$" or "$tag$"). A bare "$1" (an ordinal parameter) is NOT a dollar
// quote and returns ok=false.
func dollarTag(s string) (string, bool) {
	if len(s) < 2 || s[0] != '$' {
		return "", false
	}
	// Tag: letters, digits, underscore — but must not start with a digit, and an
	// all-empty tag ($$) is valid. A leading digit means it's a $N parameter.
	j := 1
	for j < len(s) {
		ch := s[j]
		if ch == '$' {
			return s[:j+1], true
		}
		isLetter := ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
		isDigit := ch >= '0' && ch <= '9'
		if isDigit && j == 1 {
			// $N — an ordinal parameter, not a dollar-quote opener.
			return "", false
		}
		if !isLetter && !isDigit {
			return "", false
		}
		j++
	}
	return "", false
}

// itoa renders a small positive int without importing strconv into the hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
