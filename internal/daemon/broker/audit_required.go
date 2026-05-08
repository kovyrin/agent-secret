package broker

import (
	"context"
	"fmt"

	"github.com/kovyrin/agent-secret/internal/audit"
)

func preflightRequiredAudit(ctx context.Context, sink AuditSink) error {
	if err := sink.Preflight(ctx); err != nil {
		return requiredAuditError(err)
	}
	return nil
}

func recordRequiredAudit(ctx context.Context, sink AuditSink, event audit.Event) error {
	if err := sink.Record(ctx, event); err != nil {
		return requiredAuditError(err)
	}
	return nil
}

func recordTerminalRequiredAudit(ctx context.Context, sink AuditSink, event audit.Event) error {
	auditCtx, cancel := terminalAuditContext(ctx)
	defer cancel()
	return recordRequiredAudit(auditCtx, sink, event)
}

func requiredAuditError(err error) error {
	return fmt.Errorf("%w: %w", ErrAuditRequired, err)
}
