package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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
	Hostname            string    `json:"hostname"`
	Ip                  string    `json:"ip"`
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

	// Create a flag to specify the file to read using the flag package
	filename := flag.String("file", "", "The file to read")
	outputFile := flag.String("output", "", "The file to write the results to")
	flag.Parse()

	if *filename == "" {
		fmt.Println("Please specify a file to read")
		os.Exit(0)
	}

	if *outputFile == "" {
		fmt.Println("Please specify a file to write the results to")
		os.Exit(0)
	}

	// Read the file
	file, err := ioutil.ReadFile(*filename)
	if err != nil {
		panic(err)
	}

	// Unmarshal the JSON into a struct
	var prism Prism
	err = json.Unmarshal(file, &prism)
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup

	for issueIndex, issue := range prism.Issues {
		for refIndex := range issue.References {
			wg.Add(1)
			go func(prismIssueIndex int, prismRefIndex int) {
				defer wg.Done()
				if strings.Contains(prism.Issues[prismIssueIndex].References[prismRefIndex], "nessus.org/u?") {

					// Do a HTTP request to the URL and get the redirect URL
					resp, err := http.Get(prism.Issues[prismIssueIndex].References[prismRefIndex])
					if err != nil {
						log.Println(err)
					}

					// Get the redirect URL
					updatedReference := resp.Request.URL.String()

					prism.Issues[prismIssueIndex].References[prismRefIndex] = updatedReference
				}
			}(issueIndex, refIndex)
		}

		// Check the CVSS score
		if issue.CvssVector != nil {
			if strings.Contains(*issue.CvssVector, "CVSS:3.0") {
				// Convert the CVSS score from CVSS:3.0 to CVSS:3.1
				*prism.Issues[issueIndex].CvssVector = strings.Replace(*prism.Issues[issueIndex].CvssVector, "CVSS:3.0", "CVSS:3.1", 1)
			}
		}
	}

	wg.Wait()

	// Marshal the struct back into JSON
	json, err := json.MarshalIndent(prism, "", "  ")
	if err != nil {
		panic(err)
	}

	// Write the JSON to a file
	err = ioutil.WriteFile(*outputFile, json, 0644)
	if err != nil {
		panic(err)
	}
}
