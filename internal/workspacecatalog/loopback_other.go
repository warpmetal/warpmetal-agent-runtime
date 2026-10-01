//go:build !linux

package workspacecatalog

// hostLoopBackingFile cannot name a loop backing file on this host: there are
// no loop devices, so only the persisted image identity can speak.
func hostLoopBackingFile(uint64) (string, error) {
	return "", errLoopBackingUnavailable
}
