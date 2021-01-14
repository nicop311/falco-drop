package outputs

import (
	"github.com/falcosecurity/falcosidekick/types"
	"log"
)

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type teamsSection struct {
	ActivityTitle    string      `json:"activityTitle"`
	ActivitySubTitle string      `json:"activitySubtitle"`
	ActivityImage    string      `json:"activityImage,omitempty"`
	Text             string      `json:"text"`
	Facts            []teamsFact `json:"facts,omitempty"`
}

// Payload
type teamsPayload struct {
	Type       string         `json:"@type"`
	Summary    string         `json:"summary,omitempty"`
	ThemeColor string         `json:"themeColor,omitempty"`
	Sections   []teamsSection `json:"sections"`
}

func newTeamsPayload(falcopayload types.FalcoPayload, config *types.Configuration) teamsPayload {
	var (
		sections []teamsSection
		section  teamsSection
		facts    []teamsFact
		fact     teamsFact
	)

	section.ActivityTitle = "Falco Sidekick"
	section.ActivitySubTitle = falcopayload.Time.String()

	if config.Teams.OutputFormat == All || config.Teams.OutputFormat == "text" || config.Teams.OutputFormat == "" {
		section.Text = falcopayload.Output
	}

	if config.Teams.ActivityImage != "" {
		section.ActivityImage = config.Teams.ActivityImage
	}

	if config.Teams.OutputFormat == All || config.Teams.OutputFormat == "facts" || config.Teams.OutputFormat == "" {
		for i, j := range falcopayload.OutputFields {
			switch v := j.(type) {
			case string:
				fact.Name = i
				fact.Value = v
			default:
				continue
			}

			facts = append(facts, fact)
		}

		fact.Name = Rule
		fact.Value = falcopayload.Rule
		facts = append(facts, fact)
		fact.Name = Priority
		fact.Value = falcopayload.Priority.String()
		facts = append(facts, fact)
	}

	section.Facts = facts

	var color string
	switch falcopayload.Priority {
	case types.Emergency:
		color = "e20b0b"
	case types.Alert:
		color = "ff5400"
	case types.Critical:
		color = "ff9000"
	case types.Error:
		color = "ffc700"
	case types.Warning:
		color = "ffff00"
	case types.Notice:
		color = "5bffb5"
	case types.Informational:
		color = "68c2ff"
	case types.Debug:
		color = "ccfff2"
	}

	sections = append(sections, section)

	t := teamsPayload{
		Type:       "MessageCard",
		Summary:    falcopayload.Output,
		ThemeColor: color,
		Sections:   sections,
	}

	return t
}

// TeamsPost posts event to Teams
func (c *Client) TeamsPost(falcopayload types.FalcoPayload) {
	c.Stats.Teams.Add(Total, 1)

	err := c.Post(newTeamsPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:teams", "status:error"})
		c.Stats.Teams.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "teams", "status": Error}).Inc()
		log.Printf("[ERROR] : Teams - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:teams", "status:ok"})
	c.Stats.Teams.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "teams", "status": OK}).Inc()
	log.Printf("[INFO] : Teams - Publish OK\n")
}
