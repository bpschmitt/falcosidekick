package outputs

import (
	"encoding/json"
	"log"
	"regexp"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/jeremywohl/flatten"
)

const (
	// NewRelicPath is the path of New Relic's Event API
	NewRelicPath string = "/v1/accounts"
)

type newRelicPayload struct {
	EventType         string   `json:"eventType,omitempty"`
	Title             string   `json:"title,omitempty"`
	Text              string   `json:"text,omitempty"`
	AlertType         string   `json:"alertType,omitempty"`
	SourceType        string   `json:"sourceType,omitempty"`
	Tags              []string `json:"tags,omitempty"`
	K8sPod            string   `json:"podName,omitempty"`
	K8sContainer      string   `json:"containerName,omitempty"`
	K8sContainerImage string   `json:"containerImage,omitempty"`
	K8sContainerId    string   `json:"containerId,omitempty"`
	K8sNamespace      string   `json:"namespaceName,omitempty"`
}

// Parse K8s attributes
func parseK8sAttributes(src string) map[string]string {
	//log.Println("parseK8sAttributes: " + src)
	var rex = regexp.MustCompile("([A-Za-z0-9\\-\\_\\.]+)=([A-Za-z0-9\\-\\_/]+)")
	data := rex.FindAllStringSubmatch(src, -1)

	res := make(map[string]string)
	for _, kv := range data {
		k := kv[1]
		v := kv[2]
		res[k] = v
	}
	//log.Println("k8s.pod: " + res[`k8s.pod`])
	return res
}

func newNewRelicPayload(falcopayload types.FalcoPayload) newRelicPayload {
	var d newRelicPayload
	var tags map[string]string

	tags = parseK8sAttributes(falcopayload.Output)

	//log.Println(tags)
	//log.Println("Text: " + falcopayload.Output)

	log.Println(tags[`image`])

	d.K8sPod = tags[`k8s.pod`]
	d.K8sNamespace = tags[`k8s.ns`]
	d.K8sContainerImage = tags[`image`]
	d.K8sContainerId = tags[`container_id`]

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
	c.Stats.Newrelic.Add(Total, 1)
	c.AddHeader("Api-Key", c.Config.Newrelic.LicenseKey)
	c.AddHeader("Content-Type", "application/json")
	//c.AddHeader("Content-Encoding", "gzip")

	var p newRelicPayload
	var res newRelicPayload

	p = newNewRelicPayload(falcopayload)
	pflat, err := json.Marshal(p)
	flat, err := flatten.FlattenString(string(pflat), "", flatten.UnderscoreStyle)
	json.Unmarshal([]byte(flat), &res)

	//log.Printf(string(flat))

	err = c.Post(res)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:newrelic", "status:error"})
		c.Stats.Newrelic.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "newrelic", "status": Error}).Inc()
		log.Printf("[ERROR] : New Relic - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:newrelic", "status:ok"})
	c.Stats.Newrelic.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "newrelic", "status": OK}).Inc()
}
