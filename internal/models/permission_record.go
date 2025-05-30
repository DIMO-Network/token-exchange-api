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
	Grantor     Address     `json:"grantor"`
	Grantee     Address     `json:"grantee"`
	EffectiveAt time.Time   `json:"effectiveAt"`
	ExpiresAt   time.Time   `json:"expiresAt"`
	Asset       string      `json:"asset,omitempty"`
	Agreements  []Agreement `json:"agreements"`
}

// Agreement represents a permission agreement for an asset
type Agreement struct {
	Type        string       `json:"type"`
	EventType   string       `json:"eventType"`
	IDs         []string     `json:"ids"`
	EffectiveAt time.Time    `json:"effectiveAt"`
	ExpiresAt   time.Time    `json:"expiresAt"`
	Source      string       `json:"source"`
	Asset       string       `json:"asset"`
	Permissions []Permission `json:"permissions"`
}

// Permission defines a single permission
type Permission struct {
	Name string `json:"name"`
}

// Address represents a blockchain address
type Address struct {
	Address string `json:"address"`
}
