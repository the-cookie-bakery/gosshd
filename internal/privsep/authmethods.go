package privsep

func initialAuthMethods(alternatives [][]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, alt := range alternatives {
		if len(alt) == 0 {
			continue
		}
		method := alt[0]
		if seen[method] {
			continue
		}
		seen[method] = true
		out = append(out, method)
	}
	return out
}

func authStep(alternatives [][]string, done []string, method string) (final bool, next []string, newDone []string, ok bool) {
	sequence := append(append([]string(nil), done...), method)
	if len(alternatives) == 0 {
		return true, nil, sequence, true
	}
	full := false
	prefix := false
	seenNext := map[string]bool{}
	for _, alt := range alternatives {
		if len(sequence) > len(alt) {
			continue
		}
		match := true
		for i := range sequence {
			if sequence[i] != alt[i] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if len(sequence) == len(alt) {
			full = true
			break
		}
		prefix = true
		nextMethod := alt[len(sequence)]
		if !seenNext[nextMethod] {
			seenNext[nextMethod] = true
			next = append(next, nextMethod)
		}
	}
	if full {
		return true, nil, sequence, true
	}
	if prefix {
		return false, next, sequence, true
	}
	return false, nil, done, false
}
