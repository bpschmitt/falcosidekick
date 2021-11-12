package outputs

import (
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// NewRelicPath is the path of New Relic's event API
	NewRelicPath string = "/v1/accounts"
)

type newRelicPayload struct {
	EventType  string   `json:"eventType,omitempty"`
	Title      string   `json:"title,omitempty"`
	Text       string   `json:"text,omitempty"`
	AlertType  string   `json:"alert_type,omitempty"`
	SourceType string   `json:"source_type_name,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

func newNewRelicPayload(falcopayload types.FalcoPayload) newRelicPayload {
	var d newRelicPayload
	var tags []string

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			tags = append(tags, i+":"+v)
		default:
			continue
		}
	}
	d.Tags = tags

	d.Title = falcopayload.Rule
	d.Text = falcopayload.Output
	d.SourceType = "falco"

	var status string
	switch falcopayload.Priority {
	case types.Emergency, types.Alert, types.Critical, types.Error:
		status = Error
	case types.Warning:
		status = Warning
	default:
		status = Info
	}
	d.AlertType = status
	d.EventType = "FalcoEvent"

	return d
}

// NewrelicPost posts event to New Relic
func (c *Client) NewrelicPost(falcopayload types.FalcoPayload) {
	//c.Stats.Newrelic.Add(Total, 1)
	c.AddHeader("Api-Key", c.Config.Newrelic.LicenseKey)
	c.AddHeader("Content-Type", "application/json")
	//c.AddHeader("Content-Encoding", "gzip")

	err := c.Post(newNewRelicPayload(falcopayload))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:newrelic", "status:error"})
		c.Stats.Newrelic.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "newrelic", "status": Error}).Inc()
		log.Printf("[ERROR] : New Relic - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:newrelic", "status:ok"})
	//c.Stats.Newrelic.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "newrelic", "status": OK}).Inc()
}
