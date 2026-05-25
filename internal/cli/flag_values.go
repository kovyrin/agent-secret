package cli

import (
	"fmt"
	"strings"

	"github.com/kovyrin/agent-secret/internal/request"
)

type secretFlags struct {
	specs []request.SecretSpec
}

func (s *secretFlags) String() string {
	return fmt.Sprintf("%d secret mapping(s)", len(s.specs))
}

func (s *secretFlags) Set(value string) error {
	alias, ref, ok := strings.Cut(value, "=")
	if !ok || alias == "" || ref == "" {
		return fmt.Errorf("%w: --secret must be ALIAS=op://vault/item/field, for example API_TOKEN=op://Example/Item/token", ErrInvalidArguments)
	}
	s.specs = append(s.specs, request.SecretSpec{Alias: alias, Ref: ref})
	return nil
}

type onlyFlags struct {
	aliases []string
}

func (o *onlyFlags) String() string {
	return strings.Join(o.aliases, ",")
}

func (o *onlyFlags) Set(value string) error {
	for rawAlias := range strings.SplitSeq(value, ",") {
		alias := strings.TrimSpace(rawAlias)
		if alias == "" {
			return fmt.Errorf("%w: --only must name non-empty aliases", ErrInvalidArguments)
		}
		o.aliases = append(o.aliases, alias)
	}
	return nil
}

type envFileFlags struct {
	paths []string
}

func (e *envFileFlags) String() string {
	return strings.Join(e.paths, ",")
}

func (e *envFileFlags) Set(value string) error {
	path := strings.TrimSpace(value)
	if path == "" {
		return fmt.Errorf("%w: --env-file requires a path", ErrInvalidArguments)
	}
	e.paths = append(e.paths, path)
	return nil
}

type repeatedStringFlags struct {
	values []string
	name   string
}

func (f *repeatedStringFlags) String() string {
	return strings.Join(f.values, ",")
}

func (f *repeatedStringFlags) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		name := f.name
		if name == "" {
			name = "value"
		}
		return fmt.Errorf("%w: --%s requires a non-empty value", ErrInvalidArguments, name)
	}
	f.values = append(f.values, trimmed)
	return nil
}

func indexOf(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}
