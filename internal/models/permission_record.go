package models

import (
	"time"
)

// SACDData contains the core permission data
type SACDData struct {
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
	Tags        []string     `json:"tags"`
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
