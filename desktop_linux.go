package main

import "errors"

const supportsDesktop = false

func nativeDesktop(c desktopCommand) map[string]any {
	return desktopFailure(c.ID, "not_sent", errors.New("native desktop requires Windows"))
}
