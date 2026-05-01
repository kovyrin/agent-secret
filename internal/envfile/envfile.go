package envfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var ErrInvalidEnvFile = errors.New("invalid env file")

type Entry struct {
	Key    string
	Value  string
	Source string
	Line   int
}

func Load(path string) ([]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open env file %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	return Parse(path, file)
}

func Parse(source string, reader io.Reader) ([]Entry, error) {
	scanner := bufio.NewScanner(reader)
	entries := make([]Entry, 0)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		entry, ok, err := parseLine(source, lineNumber, scanner.Text())
		if err != nil {
			return nil, err
		}
		if ok {
			entries = append(entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file %q: %w", source, err)
	}
	return entries, nil
}

func parseLine(source string, lineNumber int, line string) (Entry, bool, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return Entry{}, false, nil
	}
	if rest, ok := strings.CutPrefix(trimmed, "export "); ok {
		trimmed = strings.TrimSpace(rest)
	}

	key, rawValue, ok := strings.Cut(trimmed, "=")
	key = strings.TrimSpace(key)
	if !ok || key == "" || strings.ContainsAny(key, "=\x00") {
		return Entry{}, false, lineError(source, lineNumber, "expected KEY=VALUE")
	}

	value, err := parseValue(strings.TrimSpace(rawValue))
	if err != nil {
		return Entry{}, false, lineError(source, lineNumber, err.Error())
	}
	return Entry{Key: key, Value: value, Source: source, Line: lineNumber}, true, nil
}

func parseValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	switch raw[0] {
	case '\'':
		value, rest, ok := readSingleQuoted(raw[1:])
		if !ok {
			return "", errors.New("unterminated single-quoted value")
		}
		if err := validateTrailingComment(rest); err != nil {
			return "", err
		}
		return value, nil
	case '"':
		value, rest, ok := readDoubleQuoted(raw[1:])
		if !ok {
			return "", errors.New("unterminated double-quoted value")
		}
		if err := validateTrailingComment(rest); err != nil {
			return "", err
		}
		return value, nil
	default:
		return stripInlineComment(raw), nil
	}
}

func readSingleQuoted(raw string) (string, string, bool) {
	value, rest, ok := strings.Cut(raw, "'")
	if !ok {
		return "", "", false
	}
	return value, rest, true
}

func readDoubleQuoted(raw string) (string, string, bool) {
	var builder strings.Builder
	escaped := false
	for index, r := range raw {
		if escaped {
			switch r {
			case 'n':
				builder.WriteByte('\n')
			case 'r':
				builder.WriteByte('\r')
			case 't':
				builder.WriteByte('\t')
			case '\\', '"':
				builder.WriteRune(r)
			default:
				builder.WriteRune(r)
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			return builder.String(), raw[index+1:], true
		}
		builder.WriteRune(r)
	}
	if escaped {
		builder.WriteByte('\\')
	}
	return "", "", false
}

func validateTrailingComment(rest string) error {
	trimmed := strings.TrimSpace(rest)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil
	}
	return errors.New("unexpected characters after quoted value")
}

func stripInlineComment(raw string) string {
	for index, r := range raw {
		if r == '#' && (index == 0 || raw[index-1] == ' ' || raw[index-1] == '\t') {
			return strings.TrimSpace(raw[:index])
		}
	}
	return strings.TrimSpace(raw)
}

func lineError(source string, line int, message string) error {
	return fmt.Errorf("%w: %s:%d: %s", ErrInvalidEnvFile, source, line, message)
}
