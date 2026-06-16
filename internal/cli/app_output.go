package cli

import (
	"encoding/json"
	"fmt"
)

func (a App) writeJSON(value any) error {
	return a.writeJSONMode(value, jsonOutputPretty)
}

func (a App) writeJSONMode(value any, mode jsonOutputMode) error {
	encoder := json.NewEncoder(a.Stdout)
	if mode != jsonOutputCompact {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(value)
}

func (a App) writeJSONError(context string, err error) int {
	if writeErr := a.writeJSON(map[string]any{
		"schema_version": "1",
		"ok":             false,
		"context":        context,
		"error":          fmt.Sprintf("%s: %v", context, err),
	}); writeErr != nil {
		a.stderrf("agent-secret: write json: %v\n", writeErr)
	}
	return 1
}
