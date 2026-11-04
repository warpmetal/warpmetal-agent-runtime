//go:build !linux

package physicalgate

func observeRegisteredSourceKernel(NativeRegistration, []ProcessIdentity) (SourceKernelCut, error) {
	return SourceKernelCut{}, ErrPrerequisite
}
