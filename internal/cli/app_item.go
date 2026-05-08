package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/request"
)

func (a App) runItemDescribe(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	requestID, err := a.randomID("req")
	if err != nil {
		a.stderrf("agent-secret: generate request id: %v\n", err)
		return 1
	}
	nonce, err := a.randomID("nonce")
	if err != nil {
		a.stderrf("agent-secret: generate request nonce: %v\n", err)
		return 1
	}
	correlation := protocol.Correlation{RequestID: requestID, Nonce: nonce}
	client, payload, err := a.requestItemDescribe(ctx, manager, correlation, command.ItemDescribeRequest)
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()

	if err := a.renderItemDescribe(command.ItemDescribeFormat, command.ItemDescribePrefix, payload.Item); err != nil {
		a.stderrf("agent-secret: write item metadata: %v\n", err)
		return 1
	}
	return 0
}

func (a App) requestItemDescribe(
	ctx context.Context,
	manager daemonManager,
	correlation protocol.Correlation,
	req request.ItemDescribeRequest,
) (daemonClient, protocol.ItemDescribeResponsePayload, error) {
	return requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.ItemDescribeResponsePayload, error) {
		return client.DescribeItem(ctx, correlation, req)
	})
}

func (a App) renderItemDescribe(format itemmetadata.Format, prefix string, metadata itemmetadata.Metadata) error {
	metadata.Fields = itemmetadata.UniqueAliases(metadata.Fields, prefix)
	switch format {
	case itemmetadata.FormatText:
		return a.renderItemDescribeText(metadata)
	case itemmetadata.FormatJSON:
		encoder := json.NewEncoder(a.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(protocol.ItemDescribeResponsePayload{Item: metadata})
	case itemmetadata.FormatEnvRefs:
		return a.renderItemDescribeEnvRefs(metadata)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidArguments, format)
	}
}

func (a App) renderItemDescribeText(metadata itemmetadata.Metadata) error {
	writer := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintf(writer, "item:\t%s\n", metadata.Item); err != nil {
		return err
	}
	if metadata.Category != "" {
		if _, err := fmt.Fprintf(writer, "category:\t%s\n", metadata.Category); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "vault:\t%s\n", metadata.Vault); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "account:\t%s\n", metadata.Account); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "fields:"); err != nil {
		return err
	}
	if len(metadata.Fields) == 0 {
		if _, err := fmt.Fprintln(writer, "  (none)"); err != nil {
			return err
		}
		return writer.Flush()
	}
	if _, err := fmt.Fprintln(writer, "  alias\tlabel\ttype\tconcealed\tref"); err != nil {
		return err
	}
	for _, field := range metadata.Fields {
		label := field.Label
		if field.Section != "" {
			label = field.Section + "/" + label
		}
		if _, err := fmt.Fprintf(
			writer,
			"  %s\t%s\t%s\t%t\t%s\n",
			field.Alias,
			label,
			field.Type,
			field.Concealed,
			field.Ref,
		); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func (a App) renderItemDescribeEnvRefs(metadata itemmetadata.Metadata) error {
	for _, field := range metadata.Fields {
		if _, err := fmt.Fprintf(a.Stdout, "%s=%s\n", field.Alias, shellSingleQuote(field.Ref)); err != nil {
			return err
		}
	}
	return nil
}
