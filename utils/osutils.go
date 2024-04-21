package utils

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type execCommandResult struct {
	Output []byte
	Error  error
}

// execCommand invokes an external shell command
func execCommandWithTimeout(name string, timeoutSeconds time.Duration, args ...string) ([]byte, error) {
	log.Debugf("[%s][%d][%v]", name, timeoutSeconds, args)
	timeout := timeoutSeconds * time.Second

	cmd := exec.Command(name, args...)
	done := make(chan execCommandResult, 1)
	var result execCommandResult

	go func() {
		out, err := cmd.CombinedOutput()
		done <- execCommandResult{Output: out, Error: err}
	}()

	select {
	case <-time.After(timeout):
		if err := cmd.Process.Kill(); err != nil {
			log.Errorf("failed to kill process [%v]", err)
			result = execCommandResult{Output: nil, Error: err}
		} else {
			log.Error("process killed after timeout")
			result = execCommandResult{Output: nil, Error: errors.New("process killed after timeout")}
		}
	case result = <-done:
		break
	}
	str := sanitizeString(string(result.Output))
	log.Debugf("command[%s] output [%s] error [%s]", name, str, result.Error)
	return result.Output, result.Error
}

var xtermControlRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

func sanitizeString(s string) string {
	s = xtermControlRegex.ReplaceAllString(s, "")
	// Strip trailing newline
	s = strings.TrimSuffix(s, "\n")
	return s
}

func execCommandTimeout(cmd string, timeoutSeconds time.Duration, args ...string) (string, error) {
	log.Debugf("[%s][%d][%v]", cmd, timeoutSeconds, args)

	// Set up the context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create the command
	command := exec.CommandContext(ctx, cmd)

	// Capture output
	var output bytes.Buffer
	command.Stdout = &output

	// Execute the command
	err := command.Run()
	if err != nil {
		log.Error(err)
		return "", err
	}

	// Parse output as string
	outputString := output.String()
	out := sanitizeString(outputString)
	log.Debugf("command[%s] output [%s] error [%s]", cmd, out, err)
	return outputString, nil
}
