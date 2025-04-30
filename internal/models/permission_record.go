package models

import (
	"time"
)

// PermissionRecord represents a SACD permission record
type PermissionRecord struct {
	SpecVersion string    `json:"specversion"`
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Data        struct {
		Grantor struct {
			Address string `json:"address"`
		} `json:"grantor"`
		Grantee struct {
			Address string `json:"address"`
		} `json:"grantee"`
		EffectiveAt time.Time `json:"effectiveAt"`
		ExpiresAt   time.Time `json:"expiresAt"`
		Agreements  []struct {
			Type        string `json:"type"`
			Asset       string `json:"asset"`
			Permissions []struct {
				Name string `json:"name"`
			} `json:"permissions"`
		} `json:"agreements"`
	} `json:"data"`
}
