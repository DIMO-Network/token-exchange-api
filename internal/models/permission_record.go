package models

import (
	"time"
)

// PermissionRecord is the top-level structure for permission events
type PermissionRecord struct {
	SpecVersion string         `json:"specversion"`
	Timestamp   time.Time      `json:"timestamp"`
	Type        string         `json:"type"`
	Data        PermissionData `json:"data"`
}

// PermissionData contains the core permission data
type PermissionData struct {
	Grantor         UserInfos       `json:"grantor"`
	Grantee         UserInfos       `json:"grantee"`
	EffectiveAt     time.Time       `json:"effectiveAt"`
	ExpiresAt       time.Time       `json:"expiresAt"`
	Asset           string          `json:"asset"`
	AdditionalDates AdditionalDates `json:"additionalDates"`
	Agreements      []Agreement     `json:"agreements"`
}

// Agreement represents a permission agreement for an asset
type Agreement struct {
	Type               string       `json:"type"`
	EventType          string       `json:"eventType"`
	Asset              string       `json:"asset"`
	AttestationIDs     []string     `json:"ids"`
	EffectiveAt        *time.Time   `json:"effectiveAt"`
	ExpiresAt          *time.Time   `json:"expiresAt"`
	Source             *string      `json:"source"`
	Permissions        []Permission `json:"permissions"`
	PrivilegeIDs       []int64
	NFTContractAddress string
	Audience           []string
	Attestations       []Attestation
}

type Attestation struct {
	EventType      string   `json:"eventType"`
	Source         *string  `json:"source"`
	AttestationIDs []string `json:"id"`
}

// Permission defines a single permission
type Permission struct {
	Name string `json:"name"`
}

// UserInfos represents the grantee/ grantor infos
type UserInfos struct {
	Address string   `json:"address"`
	Name    string   `json:"name"`
	AddInfo AddInfos `json:"additionalInfo"`
}

type AddInfos struct {
	Email string `json:"email"`
}

type AdditionalDates struct {
	NextPaymentDue time.Time `json:"nextPaymentDue"`
}
