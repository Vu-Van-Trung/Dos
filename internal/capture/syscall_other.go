//go:build !windows

package capture

import "syscall"

func hiddenWindow() *syscall.SysProcAttr { return nil }
