package providerpolicy

import "errors"

type Usage struct {
	InputTokens       int64 `json:"inputTokens"`
	OutputTokens      int64 `json:"outputTokens"`
	CachedInputTokens int64 `json:"cachedInputTokens"`
}

func UsageCost(digest string, u Usage) (int64, error) {
	p, ok := Select(digest)
	if !ok || u.InputTokens < 0 || u.InputTokens > int64(p.Request.InputTokenUpperBound) || u.OutputTokens < 0 || u.OutputTokens > int64(p.Request.MaxOutputTokens) || u.CachedInputTokens < 0 || u.CachedInputTokens > u.InputTokens {
		return 0, errors.New("invalid provider usage")
	}
	cost := (u.InputTokens*p.Accounting.InputMicrosPerMillion + u.OutputTokens*p.Accounting.OutputMicrosPerMillion + 999999) / 1000000
	if cost > p.Accounting.RequestReserveMicros {
		return 0, errors.New("provider usage exceeds reserve")
	}
	return cost, nil
}
