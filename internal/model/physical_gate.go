package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const PhysicalWireMaximum = 65536

var physicalID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var physicalDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var ErrPhysicalWire = errors.New("physical gate wire refused")

type PhysicalRPCRequest struct {
	FormatVersion int             `json:"formatVersion"`
	Action        string          `json:"action"`
	OperationID   string          `json:"operationId"`
	Body          json.RawMessage `json:"body"`
}
type PhysicalRPCResponse struct {
	FormatVersion int     `json:"formatVersion"`
	OperationID   string  `json:"operationId"`
	Status        string  `json:"status"`
	Error         *string `json:"error"`
}
type PhysicalAdmitRequest struct {
	Consumer           string `json:"consumer"`
	PreparationID      string `json:"preparationId"`
	RequestIndex       int    `json:"requestIndex"`
	OuterPhysicalIndex int    `json:"outerPhysicalIndex"`
	InnerPhysicalIndex *int   `json:"innerPhysicalIndex"`
	AuthorityDigest    string `json:"authorityDigest"`
	RequestDigest      string `json:"requestDigest"`
}
type PhysicalSettlement struct {
	RequestDigest     string `json:"requestDigest"`
	ResponseDigest    string `json:"responseDigest"`
	ResponseByteCount int    `json:"responseByteCount"`
	HTTPStatus        int    `json:"httpStatus"`
	UsageUsdMicros    int64  `json:"usageUsdMicros"`
	EvidenceDigest    string `json:"evidenceDigest"`
}

func RawPhysicalDigest(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
func PhysicalIDValid(s string) bool       { return physicalID.MatchString(s) }
func PhysicalDigestValid(s string) bool   { return physicalDigest.MatchString(s) }
func DecodePhysicalClosed(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > PhysicalWireMaximum || rejectDuplicateJSONFields(raw) != nil {
		return ErrPhysicalWire
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return ErrPhysicalWire
	}
	return nil
}
func DecodePhysicalRequest(raw []byte) (PhysicalRPCRequest, error) {
	var r PhysicalRPCRequest
	var outer map[string]json.RawMessage
	if DecodePhysicalClosed(raw, &r) != nil || json.Unmarshal(raw, &outer) != nil || len(outer) != 4 || r.FormatVersion != 1 || !PhysicalIDValid(r.OperationID) {
		return r, ErrPhysicalWire
	}
	switch r.Action {
	case "admit":
		var b PhysicalAdmitRequest
		var fields map[string]json.RawMessage
		if DecodePhysicalClosed(r.Body, &b) != nil || json.Unmarshal(r.Body, &fields) != nil || len(fields) != 7 || b.Validate() != nil {
			return r, ErrPhysicalWire
		}
	case "settle":
		var b PhysicalSettlement
		var fields map[string]json.RawMessage
		if DecodePhysicalClosed(r.Body, &b) != nil || json.Unmarshal(r.Body, &fields) != nil || len(fields) != 6 || b.Validate() != nil {
			return r, ErrPhysicalWire
		}
	case "status":
		if !bytes.Equal(bytes.TrimSpace(r.Body), []byte("{}")) {
			return r, ErrPhysicalWire
		}
	default:
		return r, ErrPhysicalWire
	}
	return r, nil
}
func (b PhysicalAdmitRequest) Validate() error {
	if !PhysicalIDValid(b.PreparationID) || b.RequestIndex < 1 || b.OuterPhysicalIndex < 1 || !PhysicalDigestValid(b.AuthorityDigest) || !PhysicalDigestValid(b.RequestDigest) {
		return ErrPhysicalWire
	}
	switch b.Consumer {
	case "parent", "product", "access":
		if b.InnerPhysicalIndex != nil {
			return ErrPhysicalWire
		}
	case "qualification":
		if b.InnerPhysicalIndex == nil || *b.InnerPhysicalIndex < 1 {
			return ErrPhysicalWire
		}
	default:
		return ErrPhysicalWire
	}
	return nil
}
func (b PhysicalSettlement) Validate() error {
	if !PhysicalDigestValid(b.RequestDigest) || !PhysicalDigestValid(b.ResponseDigest) || !PhysicalDigestValid(b.EvidenceDigest) || b.ResponseByteCount < 0 || b.HTTPStatus < 100 || b.HTTPStatus > 599 || b.UsageUsdMicros < 0 {
		return ErrPhysicalWire
	}
	return nil
}
