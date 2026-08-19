package capacity

import (
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func Detect(_ string) (model.Resources, error) {
	return model.Resources{}, errors.New("warpmetald requires a Linux cgroups v2 host")
}
