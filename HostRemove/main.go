package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

type Prism struct {
	Issues  []Issue `json:"issues"`
	Version int64   `json:"version"`
	Phase   Phase   `json:"phase"`
}

type Phase struct {
	ApprovedBy       *interface{} `json:"approved_by"`
	ApprovedDate     *interface{} `json:"approved_date"`
	Caveat           string       `json:"caveat"`
	CompletedBy      *interface{} `json:"completed_by"`
	EndDate          string       `json:"end_date"`
	ExecutiveSummary string       `json:"executive_summary"`
	Location         string       `json:"location"`
	Name             string       `json:"name"`
	QaStatus         string       `json:"qa_status"`
	ScopeSummary     string       `json:"scope_summary"`
	StartDate        string       `json:"start_date"`
	Status           string       `json:"status"`
	TestType         string       `json:"test_type"`
	Tester           string       `json:"tester"`
}

type Issue struct {
	AffectedHosts           []AffectedHost `json:"affected_hosts"`
	Assignee                *string        `json:"assignee"`
	Assignees               *[]string      `json:"assignees"`
	ClientDefinedRiskRating *string        `json:"client_defined_risk_rating"`
	ConfirmedAt             string         `json:"confirmed_at"`
	Cves                    *[]string      `json:"cves"`
	CvssVector              *string        `json:"cvss_vector"`
	ExploitAvailable        *bool          `json:"exploit_available"`
	Finding                 string         `json:"finding"`
	Id                      *int64         `json:"id"`
	Name                    string         `json:"name"`
	NessusId                *int           `json:"nessus_id"`
	OriginalRiskRating      string         `json:"original_risk_rating"`
	OwaspId                 *string        `json:"owasp_id"`
	PublishedAt             *string        `json:"published_at"`
	Rapid7Id                *string        `json:"rapid7_id"`
	Recommendation          *string        `json:"recommendation"`
	References              []string       `json:"references"`
	RemediatedAt            *string        `json:"remediated_at"`
	Status                  string         `json:"status"`
	Summary                 *string        `json:"summary"`
	SuppressForProject      *bool          `json:"suppress_for_project"`
	SuppressOnAllProjects   *bool          `json:"suppress_on_all_projects"`
	SuppressUntil           *string        `json:"suppress_until"`
	TechnicalDetails        string         `json:"technical_details"`
}

type AffectedHost struct {
	Cpes                *[]string `json:"cpes"`
	Hostname            *string   `json:"hostname"`
	Ip                  *string   `json:"ip"`
	Location            *string   `json:"location"`
	Name                *string   `json:"name"`
	OperatingSystem     *string   `json:"operating_system"`
	Port                *int      `json:"port"`
	Protocol            *string   `json:"protocol"`
	Service             *string   `json:"service"`
	Status              *string   `json:"status"`
	SuppressAllProjects *bool     `json:"suppress_all_projects"`
	SuppressProject     *bool     `json:"suppress_project"`
	SuppressUntil       *string   `json:"suppress_until"`
}

func main() {

	// Read in file of hosts to remove
	hostFile := flag.String("f", "", "File containing hosts to remove")
	prismFile := flag.String("p", "", "Prism file to remove hosts from")
	outputFile := flag.String("o", "", "Prism file to remove hosts from")
	flag.Parse()

	if *hostFile == "" {
		log.Fatal("Host file not specified")
	}

	if *prismFile == "" {
		log.Fatal("Prism file not specified")
	}

	// Read the file of hosts to remove
	fHostsFile, err := os.Open(*hostFile)
	if err != nil {
		log.Fatal(err)
	}
	defer fHostsFile.Close()

	// Read the prism file
	fPrismFile, err := os.Open(*prismFile)
	if err != nil {
		log.Fatal(err)
	}
	defer fPrismFile.Close()

	// Read the prism file into a struct
	var prism Prism
	jsonParser := json.NewDecoder(fPrismFile)
	if err = jsonParser.Decode(&prism); err != nil {
		log.Fatal(err)
	}

	var hostsToRemove []string
	fileScanner := bufio.NewScanner(fHostsFile)
	for fileScanner.Scan() {
		if fileScanner.Text() == "" {
			continue
		}
		hostsToRemove = append(hostsToRemove, fileScanner.Text())
	}

	// Loop through the issues and remove the hosts
	lenPrismIssues := len(prism.Issues)
	for issueIndex := 0; issueIndex < lenPrismIssues; issueIndex++ {

		lenAffectedHosts := len(prism.Issues[issueIndex].AffectedHosts)
		for affectedHostIndex := 0; affectedHostIndex < lenAffectedHosts; affectedHostIndex++ {
			for _, hostToRemove := range hostsToRemove {

				// Remove the host if it matches
				if prism.Issues[issueIndex].AffectedHosts[affectedHostIndex].Ip != nil && *prism.Issues[issueIndex].AffectedHosts[affectedHostIndex].Ip == hostToRemove {

					fmt.Println("Removing host", hostToRemove, "from issue", prism.Issues[issueIndex].Name)
					prism.Issues[issueIndex].AffectedHosts = append(prism.Issues[issueIndex].AffectedHosts[:affectedHostIndex], prism.Issues[issueIndex].AffectedHosts[affectedHostIndex+1:]...)

					// Remove the issue if there are no more hosts
					if len(prism.Issues[issueIndex].AffectedHosts) == 0 {
						prism.Issues = append(prism.Issues[:issueIndex], prism.Issues[issueIndex+1:]...)
						issueIndex--
						lenPrismIssues--
					}

					// Update the length of the affected hosts
					lenAffectedHosts = len(prism.Issues[issueIndex].AffectedHosts)
					affectedHostIndex--
					break
				}
			}
		}
	}

	// Write the prism file back out
	fOutputFile, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer fOutputFile.Close()

	jsonEncoder := json.NewEncoder(fOutputFile)
	jsonEncoder.SetIndent("", "  ")
	if err = jsonEncoder.Encode(prism); err != nil {
		log.Fatal(err)
	}
}
