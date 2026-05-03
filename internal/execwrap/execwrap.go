package execwrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

var ErrEnvironmentConflict = errors.New("approved alias already exists in parent environment")
var ErrExecutableChanged = errors.New("approved executable changed before spawn")
var ErrMutableExecutable = errors.New("mutable executable requires explicit opt-in")

const terminateGracePeriod = 2 * time.Second

type AuditSink interface {
	Record(ctx context.Context, event AuditEvent) error
}

type AuditEvent struct {
	Type          string   `json:"type"`
	Command       []string `json:"command,omitempty"`
	CWD           string   `json:"cwd,omitempty"`
	SecretAliases []string `json:"secret_aliases,omitempty"`
	ChildPID      int      `json:"child_pid,omitempty"`
	ExitCode      int      `json:"exit_code,omitempty"`
	Signal        string   `json:"signal,omitempty"`
}

type Spec struct {
	Path                   string
	PathIdentity           fileidentity.Identity
	Args                   []string
	Dir                    string
	BaseEnv                []string
	Env                    map[string]string
	SecretAliases          []string
	OverrideEnv            bool
	AllowMutableExecutable bool
	Stdin                  io.Reader
	Stdout                 io.Writer
	Stderr                 io.Writer
	Audit                  AuditSink
}

type Result struct {
	ExitCode int
	Signal   os.Signal
}

func Run(ctx context.Context, spec Spec, interrupts <-chan os.Signal) (Result, error) {
	if spec.Path == "" {
		return Result{}, errors.New("command path is required")
	}
	if err := fileidentity.Verify(spec.Path, spec.PathIdentity); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrExecutableChanged, err)
	}
	if !spec.AllowMutableExecutable {
		if err := fileidentity.ValidateStableExecutable(spec.Path); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrMutableExecutable, err)
		}
	}

	baseEnv := spec.BaseEnv
	if baseEnv == nil {
		baseEnv = os.Environ()
	} else {
		baseEnv = slices.Clone(baseEnv)
	}
	env, err := MergeEnv(baseEnv, spec.Env, spec.OverrideEnv)
	if err != nil {
		return Result{}, err
	}

	argv := append([]string{spec.Path}, spec.Args...)
	if err := record(ctx, spec.Audit, AuditEvent{
		Type:          "command_starting",
		Command:       argv,
		CWD:           spec.Dir,
		SecretAliases: sortedAliases(spec.SecretAliases),
	}); err != nil {
		return Result{}, err
	}

	stdin := readerOrDefault(spec.Stdin, os.Stdin)
	commandContext := context.Background()
	if ctx != nil {
		commandContext = context.WithoutCancel(ctx)
	}
	//nolint:gosec // G204: command path and argv come from a daemon-approved ExecSpec after request validation and audit.
	cmd := exec.CommandContext(commandContext, spec.Path, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = writerOrDefault(spec.Stdout, os.Stdout)
	cmd.Stderr = writerOrDefault(spec.Stderr, os.Stderr)
	setProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start child: %w", err)
	}

	restoreTerminal, err := foregroundChild(cmd.Process, stdin)
	if err != nil {
		_ = terminateChild(cmd.Process)
		_, _ = cmd.Process.Wait()
		return Result{}, err
	}

	if err := record(ctx, spec.Audit, AuditEvent{
		Type:          "command_started",
		Command:       argv,
		CWD:           spec.Dir,
		SecretAliases: sortedAliases(spec.SecretAliases),
		ChildPID:      cmd.Process.Pid,
	}); err != nil {
		_ = terminateChild(cmd.Process)
		_, _ = cmd.Process.Wait()
		_ = restoreTerminal()
		return Result{}, err
	}

	done := make(chan struct{})
	go forwardInterrupts(done, cmd.Process, interrupts)
	go terminateOnContext(done, cmd.Process, ctx)

	waitErr := cmd.Wait()
	close(done)
	restoreErr := restoreTerminal()

	result := resultFromState(cmd.ProcessState)
	childPID := cmd.Process.Pid
	if cmd.ProcessState != nil {
		childPID = cmd.ProcessState.Pid()
	}
	event := AuditEvent{
		Type:          "command_completed",
		Command:       argv,
		CWD:           spec.Dir,
		SecretAliases: sortedAliases(spec.SecretAliases),
		ChildPID:      childPID,
		ExitCode:      result.ExitCode,
	}
	if result.Signal != nil {
		event.Signal = result.Signal.String()
	}
	if err := record(ctx, spec.Audit, event); err != nil {
		return result, err
	}

	if waitErr != nil && cmd.ProcessState == nil {
		return result, fmt.Errorf("wait for child: %w", waitErr)
	}
	if restoreErr != nil {
		return result, fmt.Errorf("restore terminal foreground process group: %w", restoreErr)
	}

	return result, nil
}

func MergeEnv(base []string, overlay map[string]string, override bool) ([]string, error) {
	positions := make(map[string]int, len(base))
	out := slices.Clone(base)

	for i, entry := range out {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			positions[key] = i
		}
	}

	aliases := make([]string, 0, len(overlay))
	for alias := range overlay {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)

	for _, alias := range aliases {
		value := overlay[alias]
		entry := alias + "=" + value
		if pos, exists := positions[alias]; exists {
			if !override {
				return nil, fmt.Errorf("%w: %s", ErrEnvironmentConflict, alias)
			}
			out[pos] = entry
			continue
		}

		positions[alias] = len(out)
		out = append(out, entry)
	}

	return out, nil
}

func forwardInterrupts(done <-chan struct{}, process *os.Process, interrupts <-chan os.Signal) {
	if interrupts == nil {
		return
	}

	seen := 0
	for {
		select {
		case <-done:
			return
		case sig, ok := <-interrupts:
			if !ok {
				return
			}
			if sig != nil {
				seen++
				if seen == 1 {
					_ = signalChild(process, sig)
				} else {
					terminateChildUntilDone(done, process)
				}
			}
		}
	}
}

func terminateOnContext(done <-chan struct{}, process *os.Process, ctx context.Context) {
	if ctx == nil {
		return
	}

	select {
	case <-done:
	case <-ctx.Done():
		terminateChildUntilDone(done, process)
	}
}

func terminateChildUntilDone(done <-chan struct{}, process *os.Process) {
	if process == nil {
		return
	}

	_ = signalChild(process, syscall.SIGTERM)
	timer := time.NewTimer(terminateGracePeriod)
	defer timer.Stop()

	select {
	case <-done:
	case <-timer.C:
		_ = signalChild(process, syscall.SIGKILL)
	}
}

func resultFromState(state *os.ProcessState) Result {
	if state == nil {
		return Result{ExitCode: -1}
	}

	result := Result{ExitCode: state.ExitCode()}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		result.Signal = status.Signal()
	}

	return result
}

func writerOrDefault(writer io.Writer, fallback io.Writer) io.Writer {
	if writer != nil {
		return writer
	}
	return fallback
}

func readerOrDefault(reader io.Reader, fallback io.Reader) io.Reader {
	if reader != nil {
		return reader
	}
	return fallback
}

func record(ctx context.Context, sink AuditSink, event AuditEvent) error {
	if sink == nil {
		return nil
	}
	if err := sink.Record(ctx, event); err != nil {
		return fmt.Errorf("record audit event %s: %w", event.Type, err)
	}
	return nil
}

func sortedAliases(aliases []string) []string {
	out := slices.Clone(aliases)
	slices.Sort(out)
	return out
}
