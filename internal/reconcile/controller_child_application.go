package reconcile

import (
	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Current accepted application identity used by child completion. This is not
// a first-task original, new workflow authority, or an execution permission.
// Callers derive it from their existing original and independently recheck the
// accepted local operation in currentCompletedChildAuthority before effects.
type controllerChildApplication struct {
	Owner                      model.ControllerOwner `json:"owner"`
	ApplicationID              string                `json:"applicationId"`
	ApplicationOperationID     string                `json:"applicationOperationId"`
	ApplicationOperationDigest string                `json:"applicationOperationDigest"`
}

func controllerChildApplicationFromFirstTask(o api.OwnerFirstTaskOriginal) controllerChildApplication {
	return controllerChildApplication{o.Owner, o.ApplicationID, o.ApplicationOperationID, o.ApplicationOperationDigest}
}
