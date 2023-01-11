package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/goark/go-cvss/v3/metric"
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
	filename := flag.String("f", "", "The file to read")
	outputFile := flag.String("o", "", "The file to write the results to")
	fixCVSS := flag.Bool("cvss", false, "Map the CVSS vector with the Severity of the issue")

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
	file, err := os.ReadFile(*filename)
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

		// Check the technical details for "Tenable ciphername" and replace it with "Ciphername"
		if strings.Contains(issue.TechnicalDetails, "Tenable ciphername") {
			fmt.Println("[+] Found Tenable ciphername in technical details, updating...")
			updatedTechnicalDetails := strings.ReplaceAll(issue.TechnicalDetails, "Tenable ciphername", "Ciphername")
			prism.Issues[issueIndex].TechnicalDetails = updatedTechnicalDetails
		}

		// Check the references for "nessus.org/u?" and replace it with the redirect URL
		for refIndex := range issue.References {
			wg.Add(1)
			go func(prismIssueIndex int, prismRefIndex int) {
				defer wg.Done()
				if strings.Contains(prism.Issues[prismIssueIndex].References[prismRefIndex], "nessus.org/u?") || strings.Contains(prism.Issues[prismIssueIndex].References[prismRefIndex], "api.tenable.com/v1/u?") {
					// Do a HTTP request to the URL and get the redirect URL
					resp, err := http.Get(prism.Issues[prismIssueIndex].References[prismRefIndex])
					if err != nil {
						log.Println(err)
					}

					// Get the redirect URL
					updatedReference := resp.Request.URL.String()
					fmt.Println("[+] Fixing Reference URL: " + prism.Issues[prismIssueIndex].References[prismRefIndex] + " -> " + updatedReference)
					prism.Issues[prismIssueIndex].References[prismRefIndex] = updatedReference
				}
			}(issueIndex, refIndex)
		}

		// Check the CVSS score
		if issue.CvssVector != nil {

			*prism.Issues[issueIndex].CvssVector = strings.TrimRight(*prism.Issues[issueIndex].CvssVector, "/")
			if *fixCVSS {
				bm, _ := metric.NewBase().Decode(*prism.Issues[issueIndex].CvssVector)
				if !strings.EqualFold(bm.Severity().String(), prism.Issues[issueIndex].OriginalRiskRating) {
					if prism.Issues[issueIndex].OriginalRiskRating == "Info" && bm.Severity().String() == "None" {
						continue
					}
					fmt.Println("[+] Fixing Severity: " + prism.Issues[issueIndex].OriginalRiskRating + " -> " + bm.Severity().String())
					prism.Issues[issueIndex].OriginalRiskRating = bm.Severity().String()
				}
			}

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
	err = os.WriteFile(*outputFile, json, 0644)
	if err != nil {
		panic(err)
	}
}
