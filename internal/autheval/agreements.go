package autheval

import (
	"slices"

	"github.com/DIMO-Network/shared/pkg/set"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
)

type CloudEventAgreements struct {
	agreements []Agreement
}

func (c *CloudEventAgreements) Add(eventType, source string, ids, tags []string) {
	if len(tags) == 0 {
		tags = []string{models.GlobalIdentifier}
	}
	if len(ids) == 0 {
		ids = []string{models.GlobalIdentifier}
	}
	c.agreements = append(c.agreements, Agreement{EventType: eventType, Source: source, IDs: set.New(ids...), Tags: set.New(tags...)})
}

func (c *CloudEventAgreements) Grants(eventType, source, ids, tags string) bool {
	return slices.ContainsFunc(c.agreements, func(a Agreement) bool { return a.Grants(eventType, source, ids, tags) })
}

type Agreement struct {
	EventType string          `json:"eventType"`
	Source    string          `json:"source"`
	IDs       set.Set[string] `json:"id"`
	Tags      set.Set[string] `json:"tags"`
}

func (a Agreement) Grants(eventType, source, ids, tags string) bool {
	return (a.EventType == eventType || a.EventType == models.GlobalIdentifier) &&
		(a.Source == source || a.Source == models.GlobalIdentifier) &&
		(a.IDs.Contains(ids) || a.IDs.Contains(models.GlobalIdentifier)) &&
		(a.Tags.Contains(tags) || a.Tags.Contains(models.GlobalIdentifier))
}
