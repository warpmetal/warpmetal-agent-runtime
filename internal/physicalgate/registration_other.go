//go:build !linux

package physicalgate

import (
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func observeNativeProcess(ContainerObservation, int) (ProcessIdentity, string, string, error) {
	return ProcessIdentity{}, "", "", ErrPrerequisite
}
func verifyNativePeer(Peer, NativeRegistration) error { return ErrPrerequisite }
func verifiedNativeSettlementOriginals(NativeRegistration, state.PhysicalOperation, model.PhysicalSettlement) (state.NativeSettlementOriginals, error) {
	return state.NativeSettlementOriginals{}, ErrPrerequisite
}
func holdNativePeer(Peer, NativeRegistration) (func() error, func(), error) {
	return nil, nil, ErrPrerequisite
}
func observeOwnAccessProcess() (ProcessIdentity, error) { return ProcessIdentity{}, ErrPrerequisite }

func verifiedNativeAdmissionOriginal(NativeRegistration, string, model.PhysicalAdmitRequest) ([]byte, error) {
	return nil, ErrPrerequisite
}
