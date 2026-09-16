// sshfm is a transparent ssh pty proxy: it forwards every byte between the
// real terminal and a real `ssh` child process untouched, so it behaves
// exactly like plain ssh, except it watches for one sequence - Enter, then
// `~f` - which pops a real `sftp` session (reusing a hidden background
// connection opened at startup) and hands the terminal back to ssh the
// moment sftp exits.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

const trigger = 'f'

func main() {
	sshArgs := os.Args[1:]
	if len(sshArgs) == 0 {
		sshPath, err := exec.LookPath("ssh")
		if err != nil {
			fmt.Fprintln(os.Stderr, "sshfm: ssh not found in PATH")
			os.Exit(127)
		}
		_ = syscall.Exec(sshPath, []string{"ssh"}, os.Environ())
	}

	host := sshArgs[len(sshArgs)-1]
	sockPath, masterErr := startMaster(sshArgs)

	cmd := exec.Command("ssh", sshArgs...)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sshfm: failed to start ssh:", err)
		os.Exit(1)
	}
	defer ptmx.Close()

	var oldState *term.State
	if term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			oldState = nil
		}
	}
	restoreTerm := func() {
		if oldState != nil {
			_ = term.Restore(int(os.Stdin.Fd()), oldState)
		}
	}
	defer restoreTerm()

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	winch <- syscall.SIGWINCH // initial size sync

	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(os.Stdout, ptmx)
		close(copyDone)
	}()

	go processStdin(ptmx, sockPath, masterErr, sshArgs, host, &oldState)

	waitErr := cmd.Wait()
	restoreTerm()
	stopMaster(sockPath, host)

	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

// startMaster opens a hidden background ControlMaster connection purely for
// sftp to reuse, keyed to this process's pid so it can't collide with
// sshfm instances in other terminals. Runs before the visible session's
// pty/raw-mode setup, so its stdio is still the plain original terminal -
// intentionally NOT BatchMode, so if the host needs a password (or an
// unrecognized host key), the normal ssh prompt appears right here and
// works exactly like typing the command directly. StrictHostKeyChecking=
// accept-new still avoids a redundant prompt for a first-time host.
func startMaster(sshArgs []string) (string, string) {
	sockDir := filepath.Join(os.Getenv("HOME"), ".ssh", "sockets")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		return "", err.Error()
	}
	sockPath := filepath.Join(sockDir, fmt.Sprintf("sshfm-%d-%s", os.Getpid(), randHex(4)))

	args := []string{
		"-o", "ControlMaster=yes",
		"-o", "ControlPersist=10m",
		"-o", "ControlPath=" + sockPath,
		"-o", "StrictHostKeyChecking=accept-new",
		"-fN",
	}
	args = append(args, sshArgs...)

	var stderr bytes.Buffer
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", msg
	}
	return sockPath, ""
}

func stopMaster(sockPath, host string) {
	if sockPath == "" {
		return
	}
	cmd := exec.Command("ssh", "-o", "ControlPath="+sockPath, "-O", "exit", host)
	_ = cmd.Run()
}

// sftpArgs translates ssh's `-p PORT` flag to sftp/scp's `-P PORT` - the one
// flag whose meaning differs between them (sftp's own `-p` means "preserve
// file attributes"). Everything else (-i, -o, -F, the destination, ...)
// means the same thing in both, so it's passed through unchanged.
func sftpArgs(sshArgs []string) []string {
	out := make([]string, len(sshArgs))
	copy(out, sshArgs)
	for i, a := range out {
		if a == "-p" && i+1 < len(out) {
			out[i] = "-P"
		}
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// processStdin forwards stdin to ptmx byte-for-byte, except for the
// sequence "\n~f" (matching ssh's own escape-key convention but never
// forwarded to ssh, so it isn't subject to ssh's restrictions on escapes
// during ControlMaster use), which triggers runSFTP instead.
func processStdin(ptmx *os.File, sockPath, masterErr string, sshArgs []string, host string, oldState **term.State) {
	buf := make([]byte, 4096)
	state := 1 // 1 == start-of-line; matches ssh treating session start as eligible too
	var out []byte

	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return
		}
		out = out[:0]
		data := buf[:n]
		for i := 0; i < len(data); i++ {
			b := data[i]
			switch state {
			case 0:
				if b == '\r' || b == '\n' {
					state = 1
				}
				out = append(out, b)
			case 1:
				switch {
				case b == '~':
					state = 2
				case b == '\r' || b == '\n':
					out = append(out, b)
				default:
					state = 0
					out = append(out, b)
				}
			case 2:
				switch {
				case b == trigger:
					if len(out) > 0 {
						_, _ = ptmx.Write(out)
						out = out[:0]
					}
					runSFTP(sockPath, masterErr, sshArgs, host, oldState)
					state = 1
				case b == '\r' || b == '\n':
					out = append(out, '~', b)
					state = 1
				default:
					out = append(out, '~', b)
					state = 0
				}
			}
		}
		if len(out) > 0 {
			_, _ = ptmx.Write(out)
		}
	}
}

func runSFTP(sockPath, masterErr string, sshArgs []string, host string, oldState **term.State) {
	if *oldState != nil {
		_ = term.Restore(int(os.Stdin.Fd()), *oldState)
	}

	if sockPath == "" {
		fmt.Fprintf(os.Stdout, "\r\n[sshfm] sftp unavailable (background connection failed): %s\r\n", masterErr)
	} else {
		args := append([]string{"-o", "ControlPath=" + sockPath}, sftpArgs(sshArgs)...)
		cmd := exec.Command("sftp", args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		st, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			*oldState = st
		}
	}
}
