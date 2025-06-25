package controllers

import (
	"testing"

	"github.com/DIMO-Network/shared/pkg/set"
	"github.com/stretchr/testify/assert"
)

func TestXxx(t *testing.T) {
	source := "0x3046f8e236b30Dc43290F72B8231915699A6d4cb"

	global := set.NewStringSet()
	global.Add("id1")

	event := set.NewStringSet()
	event.Add("id2")

	attest := set.NewStringSet()
	attest.Add("id3")

	sacdAgreements := map[string]map[string]*set.StringSet{
		"*": {
			source: global,
		},
		"dimo.event": {
			source: event,
		},
		"dimo.attestation": {
			source: attest,
		},
	}

	err := evaluateCloudEvents(sacdAgreements, &TokenRequest{
		CloudEvents: CloudEvents{
			Events: []EventFilter{
				{
					EventType: "dimo.event",
					Source:    source,
					IDs:       []string{"id1", "id2"},
				},
				{
					EventType: "dimo.attestation",
					Source:    source,
					IDs:       []string{"id2"},
				},
			},
		},
	})

	assert.Error(t, err, "The client requested id2 for dimo.attestation, to which he should not have access")
}
