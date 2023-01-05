package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

type Prism struct {
	Issues  []Issue `json:"issues"`
	Version int64   `json:"version"`
}

type Issue struct {
	AffectedHosts           []AffectedHost `json:"affected_hosts"`
	Assignee                string         `json:"assignee"`
	Assignees               []string       `json:"assignees"`
	ClientDefinedRiskRating string         `json:"client_defined_risk_rating"`
	ConfirmedAt             string         `json:"confirmed_at"`
	Cves                    []string       `json:"cves"`
	CvssVector              string         `json:"cvss_vector"`
	ExploitAvailable        bool           `json:"exploit_available"`
	Finding                 string         `json:"finding"`
	Id                      int64          `json:"id"`
	Name                    string         `json:"name"`
	NessusId                interface{}    `json:"nessus_id"`
	OriginalRiskRating      string         `json:"original_risk_rating"`
	OwaspId                 interface{}    `json:"owasp_id"`
	PublishedAt             string         `json:"published_at"`
	Rapid7Id                interface{}    `json:"rapid7_id"`
	Recommendation          string         `json:"recommendation"`
	References              []string       `json:"references"`
	RemediatedAt            interface{}    `json:"remediated_at"`
	Status                  string         `json:"status"`
	Summary                 string         `json:"summary"`
	SuppressForProject      bool           `json:"suppress_for_project"`
	SuppressOnAllProjects   bool           `json:"suppress_on_all_projects"`
	SuppressUntil           interface{}    `json:"suppress_until"`
	TechnicalDetails        string         `json:"technical_details"`
}

type AffectedHost struct {
	Cpes                []string    `json:"cpes"`
	Hostname            string      `json:"hostname"`
	Ip                  string      `json:"ip"`
	Location            string      `json:"location"`
	Name                string      `json:"name"`
	OperatingSystem     string      `json:"operating_system"`
	Port                int         `json:"port"`
	Protocol            string      `json:"protocol"`
	Service             string      `json:"service"`
	Status              string      `json:"status"`
	SuppressAllProjects bool        `json:"suppress_all_projects"`
	SuppressProject     bool        `json:"suppress_project"`
	SuppressUntil       interface{} `json:"suppress_until"`
}

type Nuclei struct {
	CurlCommand      string   `json:"curl-command"`
	ExtractedResults []string `json:"extracted-results"`
	Host             string   `json:"host"`
	Info             struct {
		Author      []string `json:"author"`
		Description string   `json:"description"`
		Name        string   `json:"name"`
		Reference   []string `json:"reference,omitempty"`
		Severity    string   `json:"severity"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Ip            string      `json:"ip"`
	MatchedAt     string      `json:"matched-at"`
	MatchedLine   interface{} `json:"matched-line"`
	MatcherStatus bool        `json:"matcher-status"`
	Template      string      `json:"template"`
	TemplateId    string      `json:"template-id"`
	TemplatePath  string      `json:"template-path"`
	TemplateUrl   string      `json:"template-url"`
	Timestamp     string      `json:"timestamp"`
	Type          string      `json:"type"`
}

func (n *Nuclei) ParseJSON() []Nuclei {
	var output []Nuclei

	// Get todays date
	today := time.Now().Format("2006-01-02")

	// read the output/nuclei/nuclei.json file line by line
	file, err := os.Open(fmt.Sprintf("output/nuclei/nuclei_output_%s.json", today))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Read the file line by line
	fs := bufio.NewScanner(file)
	for fs.Scan() {

		// Get the line
		line := fs.Bytes()

		var results Nuclei
		err = json.Unmarshal(line, &results)
		if err != nil {
			log.Fatal(err)
		}
		output = append(output, results)
	}
	return output
}

// Convert the output to a JSON file
func (n *Nuclei) ToJSON() {
	// Get todays date
	today := time.Now().Format("2006-01-02")

	// Create the output file
	file, err := os.Create(fmt.Sprintf("output/custom/nuclei_output_%s.json", today))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Write the output to the file
	for _, result := range n.ParseJSON() {
		// Convert the output to JSON
		json, err := json.Marshal(result)
		if err != nil {
			log.Fatal(err)
		}
		file.Write(json)
	}
}

// Convert the JSON to the Prism Struct
func (n *Nuclei) ToPrismJSON() {
	// Get todays date
	today := time.Now().Format("2006-01-02")

	// Create the output file
	file, err := os.Create(fmt.Sprintf("output/custom/prism_json_%s.json", today))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var prism Prism
	prism.Version = 1

	// Write the output to the file
	for _, result := range n.ParseJSON() {

		// Normalize the host
		result.Host = strings.Replace(result.Host, "http://", "", -1)
		result.Host = strings.Replace(result.Host, "https://", "", -1)

		newIssue := true
		for index, issue := range prism.Issues {
			if issue.Name == result.Info.Name {

				newIssue = false
				addHost := false

				// Check if the host already exists
				for _, affectedHost := range prism.Issues[index].AffectedHosts {
					if affectedHost.Ip == result.Ip {
						addHost = false
						break
					} else {
						addHost = true
					}
				}

				if addHost {
					var affectedHost AffectedHost
					affectedHost.Ip = result.Ip
					affectedHost.Hostname = result.Host
					// affectedHost.Port =
					prism.Issues[index].AffectedHosts = append(prism.Issues[index].AffectedHosts, affectedHost)
				}

				// Add the curl-command to the technical details
				td := prism.Issues[index].TechnicalDetails + "<p>&nbsp;</p><p>Host: " + result.Host + "<br /><table style='border-collapse: collapse; width: 100%;' border='1'><tbody><tr><td style='width: 98.5288%;'>" + result.CurlCommand + "</td></tr></tbody></table><p>&nbsp;</p>" + result.CurlCommand
				if result.ExtractedResults != nil {
					td = td + "<p>&nbsp;</p><p>Extracted Results: <br /><table style='border-collapse: collapse; width: 100%;' border='1'><tbody>"

					for _, extractedResult := range result.ExtractedResults {
						td = td + "<tr><td style='width: 98.5288%;'>" + extractedResult + "</td></tr>"
					}
				}
				prism.Issues[index].TechnicalDetails = td + "</tbody></table></p>"
			}
		}

		if newIssue {
			// Create a new issue
			var issue Issue
			issue.Name = result.Info.Name
			issue.Finding = result.Info.Description
			if result.Timestamp == "" {
				timestamp := time.Now().Format("2006-01-02")
				issue.ConfirmedAt = timestamp
			}
			issue.ConfirmedAt = result.Timestamp
			issue.OriginalRiskRating = result.Info.Severity
			issue.Status = "open"

			// Check if the host is already in the affected hosts
			var affectedHost AffectedHost
			affectedHost.Ip = result.Ip
			affectedHost.Hostname = result.Host
			issue.AffectedHosts = append(issue.AffectedHosts, affectedHost)

			td := "<p>&nbsp;</p><p>Host: " + result.Host + "<br /><table style='border-collapse: collapse; width: 100%;' border='1'><tbody><tr><td style='width: 98.5288%;'>" + result.CurlCommand + "</td></tr></tbody></table><p>&nbsp;</p>" + result.CurlCommand

			if result.ExtractedResults != nil {
				td = td + "<p>&nbsp;</p><p>Extracted Results: <br /><table style='border-collapse: collapse; width: 100%;' border='1'><tbody>"

				for _, extractedResult := range result.ExtractedResults {
					td = td + "<tr><td style='width: 98.5288%;'>" + extractedResult + "</td></tr>"
				}
			}
			td = td + "</tbody></table></p>"

			issue.TechnicalDetails = td
			var references []string
			if result.Info.Reference != nil {
				references = append(references, result.Info.Reference...)
			}
			issue.References = references
			prism.Issues = append(prism.Issues, issue)
		}
	}

	//output the results to the file
	json, err := json.Marshal(prism)
	if err != nil {
		log.Fatal(err)
	}
	file.Write(json)
}

func main() {
	n := Nuclei{}
	n.ParseJSON()
	n.ToJSON()
	n.ToPrismJSON()
}
