package honeypot

// stringMatch is a port of Redis' stringmatchlen (util.c), including the
// skipLongerMatches optimisation and nesting guard from Redis 7, so KEYS and
// CONFIG GET patterns behave like the real server: '*' and '?' also match '/',
// and [...] classes, ranges, negation and backslash escapes are supported.
func stringMatch(pattern, str string, nocase bool) bool {
	skipLonger := false
	return stringMatchImpl(pattern, str, nocase, &skipLonger, 0)
}

func stringMatchImpl(pattern, str string, nocase bool, skipLonger *bool, nesting int) bool {
	if nesting > 1000 {
		return false
	}

	p, s := 0, 0
	for p < len(pattern) && s < len(str) {
		switch pattern[p] {
		case '*':
			for p+1 < len(pattern) && pattern[p+1] == '*' {
				p++
			}
			if p+1 == len(pattern) {
				return true
			}
			for s < len(str) {
				if stringMatchImpl(pattern[p+1:], str[s:], nocase, skipLonger, nesting+1) {
					return true
				}
				if *skipLonger {
					return false
				}
				s++
			}
			*skipLonger = true
			return false
		case '?':
			s++
		case '[':
			p++
			not := p < len(pattern) && pattern[p] == '^'
			if not {
				p++
			}
			match := false
			for {
				if p >= len(pattern) {
					p--
					break
				}
				c := pattern[p]
				if c == '\\' && len(pattern)-p >= 2 {
					p++
					if pattern[p] == str[s] {
						match = true
					}
				} else if c == ']' {
					break
				} else if len(pattern)-p >= 3 && pattern[p+1] == '-' {
					start, end, ch := pattern[p], pattern[p+2], str[s]
					if start > end {
						start, end = end, start
					}
					if nocase {
						start, end, ch = lowerASCII(start), lowerASCII(end), lowerASCII(ch)
					}
					p += 2
					if ch >= start && ch <= end {
						match = true
					}
				} else if equalByte(c, str[s], nocase) {
					match = true
				}
				p++
			}
			if not {
				match = !match
			}
			if !match {
				return false
			}
			s++
		case '\\':
			if len(pattern)-p >= 2 {
				p++
			}
			fallthrough
		default:
			if !equalByte(pattern[p], str[s], nocase) {
				return false
			}
			s++
		}
		p++
		if s == len(str) {
			for p < len(pattern) && pattern[p] == '*' {
				p++
			}
			break
		}
	}
	return p == len(pattern) && s == len(str)
}

func equalByte(a, b byte, nocase bool) bool {
	if nocase {
		return lowerASCII(a) == lowerASCII(b)
	}
	return a == b
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
