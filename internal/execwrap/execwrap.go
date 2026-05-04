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

type LifecycleReporter interface {
	CommandStarted(ctx context.Context, childPID int) error
	CommandCompleted(ctx context.Context, result Result) error
}

type Spec struct {
	Path                   string
	PathIdentity           fileidentity.Identity
	Args                   []string
	Dir                    string
	BaseEnv                []string
	Env                    map[string]string
	OverrideEnv            bool
	AllowMutableExecutable bool
	Stdin                  io.Reader
	Stdout                 io.Writer
	Stderr                 io.Writer
	Lifecycle              LifecycleReporter
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

	if err := commandStarted(ctx, spec.Lifecycle, cmd.Process.Pid); err != nil {
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
	if err := commandCompleted(ctx, spec.Lifecycle, result); err != nil {
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
	aliases := make([]string, 0, len(overlay))
	for alias := range overlay {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)

	overlayAliases := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		overlayAliases[alias] = struct{}{}
	}

	out := make([]string, 0, len(base)+len(overlay))
	existing := make(map[string]struct{}, len(base))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			existing[key] = struct{}{}
			if override {
				if _, exists := overlayAliases[key]; exists {
					continue
				}
			}
		}
		out = append(out, entry)
	}

	for _, alias := range aliases {
		if _, exists := existing[alias]; exists && !override {
			return nil, fmt.Errorf("%w: %s", ErrEnvironmentConflict, alias)
		}

		out = append(out, alias+"="+overlay[alias])
	}

	return out, nil
}

func forwardInterrupts(done <-chan struct{}, process *os.Process, interrupts <-chan os.Signal) {
	if interrupts == nil {
		return
	}

	for {
		select {
		case <-done:
			return
		case sig, ok := <-interrupts:
			if !ok {
				return
			}
			if sig != nil {
				_ = signalChild(process, sig)
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

func commandStarted(ctx context.Context, reporter LifecycleReporter, childPID int) error {
	if reporter == nil {
		return nil
	}
	if err := reporter.CommandStarted(ctx, childPID); err != nil {
		return fmt.Errorf("report command started: %w", err)
	}
	return nil
}

func commandCompleted(ctx context.Context, reporter LifecycleReporter, result Result) error {
	if reporter == nil {
		return nil
	}
	if err := reporter.CommandCompleted(ctx, result); err != nil {
		return fmt.Errorf("report command completed: %w", err)
	}
	return nil
}
