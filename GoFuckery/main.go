package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/fatih/color"
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
	writeExecSummary := flag.Bool("exec", false, "Write the Executive Summary (Warning! This will overwrite the existing Executive Summary!) Also requires the ChatGPT API key to be set in the CHATGPT_API_KEY environment variable.")

	flag.Parse()

	if *filename == "" {
		fmt.Println("Please specify a file to read")
		os.Exit(0)
	}

	if *outputFile == "" {
		fmt.Println("Please specify a file to write the results to")
		os.Exit(0)
	}

	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)

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

	var issuesForExecSummary []string

	var wg sync.WaitGroup

	for issueIndex, issue := range prism.Issues {

		// Check the char length of the CVEs
		if issue.Cves != nil {
			charCount := 0
			for cveIndex, cve := range *issue.Cves {
				charCount += len(cve) + 2 // +2 for the newline chars (\r\n)
				if charCount >= 10000 {
					green.Println("[+] Found CVEs with a character count greater than 10000, removing the rest...")

					// Remove everything after the 10000 character count
					*prism.Issues[issueIndex].Cves = (*issue.Cves)[:cveIndex]

					// Verify the new character count
					c := 0
					for _, k := range *prism.Issues[issueIndex].Cves {
						c += len(k)
					}
					green.Printf("[+] New character count: %d\n", c)
					break
				}
			}
		}

		if issue.OriginalRiskRating == "Critical" || issue.OriginalRiskRating == "High" {
			issuesForExecSummary = append(issuesForExecSummary, issue.Name)
		}

		// Check the technical details for "Tenable ciphername" and replace it with "Ciphername"
		if strings.Contains(issue.TechnicalDetails, "Tenable ciphername") {
			green.Println("[+] Found Tenable ciphername in technical details, updating...")
			updatedTechnicalDetails := strings.ReplaceAll(issue.TechnicalDetails, "Tenable ciphername", "Ciphername")
			prism.Issues[issueIndex].TechnicalDetails = updatedTechnicalDetails
		}

		// Perform a regex lookup on the technical details to check for Fixed version : [0-9\.]+?</p> and remove it
		re := regexp.MustCompile(`(Should be|Fixed version)\s*:\s*[A-Za-z0-9\.\-_]*(\\u003c|\<)?`)
		if re.MatchString(issue.TechnicalDetails) {
			green.Println("[+] Found \"Fixed version\" in technical details, updating...")
			updatedTechnicalDetails := re.ReplaceAllString(issue.TechnicalDetails, "$2")
			prism.Issues[issueIndex].TechnicalDetails = updatedTechnicalDetails
		}

		// Perform a regex lookup on the technical details to remove multiple newlines
		nlRe := regexp.MustCompile(`(\<br\s?\/\>\<br\s?\/\>\<\/p\>|\\u003cbr\s?\/\\u003e\\u003cbr\s?\/\\u003e\\u003c\/p\\u003e)`)
		if nlRe.MatchString(issue.TechnicalDetails) {
			replaceNewLineTechDetails := nlRe.ReplaceAllString(issue.TechnicalDetails, "\u003c/p\u003e")
			prism.Issues[issueIndex].TechnicalDetails = replaceNewLineTechDetails
		}

		// Remove unwanted empty paragraph tags
		prism.Issues[issueIndex].TechnicalDetails = strings.ReplaceAll(prism.Issues[issueIndex].TechnicalDetails, "\u003cp\u003e\u003c/p\u003e", "")

		// Check for "remote"
		badStrings := map[string]string{
			"remote service is":        "service was",
			"remote server":            "server",
			"remote web server":        "web server",
			"The remote":               "The",
			"remote host":              "host",
			"is affected":              "was affected",
			"service allows":           "service allowed",
			"service supports":         "service supported",
			"host supports":            "host supported",
			"algorithms are supported": "algorithms were supported",
			"algorithms are enabled":   "algorithms were enabled",
			"It is, therefore,":        "It was, therefore,",
			"certificate has already":  "certificate had already",
			"service ends":             "service ended",
			"service encrypts":         "service encrypted",
			"service accepts":          "service accepted",
			"host allows":              "host allowed",
			"server allows":            "server allowed",
			"is prior":                 "was prior",
		}

		for badString, goodString := range badStrings {

			// Check the finding
			if strings.Contains(issue.Finding, badString) {
				green.Println("[+] Found \"", badString, "\" in finding, updating...")
				updatedFinding := strings.ReplaceAll(issue.Finding, badString, goodString)
				prism.Issues[issueIndex].Finding = updatedFinding
			}

			// Check the summary
			if strings.Contains(*issue.Summary, badString) {
				green.Println("[+] Found \"", badString, "\" in summary, updating...")
				updatedSummary := strings.ReplaceAll(*issue.Summary, badString, goodString)
				*prism.Issues[issueIndex].Summary = updatedSummary
			}

			// Check the Technical Details
			if strings.Contains(issue.TechnicalDetails, badString) {
				green.Println("[+] Found \"", badString, "\" in technical details, updating...")
				updatedTechnicalDetails := strings.ReplaceAll(issue.TechnicalDetails, badString, goodString)
				prism.Issues[issueIndex].TechnicalDetails = updatedTechnicalDetails
			}

			// Check the recommendation
			if strings.Contains(*issue.Recommendation, badString) {
				green.Println("[+] Found \"", badString, "\" in recommendation, updating...")
				updatedRecommendation := strings.ReplaceAll(*issue.Recommendation, badString, goodString)
				*prism.Issues[issueIndex].Recommendation = updatedRecommendation
			}
		}

		if issue.References != nil {

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
							return
						}

						// Get the redirect URL
						updatedReference := resp.Request.URL.String()
						green.Println("[+] Fixing Reference URL: " + prism.Issues[prismIssueIndex].References[prismRefIndex] + " -> " + updatedReference)
						prism.Issues[prismIssueIndex].References[prismRefIndex] = updatedReference
					}
				}(issueIndex, refIndex)
			}
		} else {
			red.Println("[-] No references found for issue: " + issue.Name)
		}

		// Check the CVSS score
		if issue.CvssVector != nil && *issue.CvssVector != "" {

			*prism.Issues[issueIndex].CvssVector = strings.TrimRight(*prism.Issues[issueIndex].CvssVector, "/")
			if *fixCVSS {
				bm, _ := metric.NewBase().Decode(*prism.Issues[issueIndex].CvssVector)
				if !strings.EqualFold(bm.Severity().String(), prism.Issues[issueIndex].OriginalRiskRating) {
					if prism.Issues[issueIndex].OriginalRiskRating == "Info" && bm.Severity().String() == "None" {
						continue
					}
					green.Println("[+] Fixing Severity: " + prism.Issues[issueIndex].OriginalRiskRating + " -> " + bm.Severity().String())
					prism.Issues[issueIndex].OriginalRiskRating = bm.Severity().String()
				}
			}

			if strings.Contains(*issue.CvssVector, "CVSS:3.0") {
				// Convert the CVSS score from CVSS:3.0 to CVSS:3.1
				*prism.Issues[issueIndex].CvssVector = strings.Replace(*prism.Issues[issueIndex].CvssVector, "CVSS:3.0", "CVSS:3.1", 1)
			}
		} else {
			red.Println("[-] No CVSS score found for issue: " + issue.Name)
		}

		if !strings.HasPrefix(*issue.Recommendation, "It is recommended ") {
			red.Println("[-] Recommendation does not start with 'It is recommended ' for issue: " + issue.Name)
		}
	}

	wg.Wait()

	if *writeExecSummary {
		// godotenv.Load()

		// apiKey := os.Getenv("CHATGPT_API_KEY")
		// if apiKey == "" {
		// 	log.Fatalln("Missing API KEY")
		// }

		// ctx := context.Background()
		// client := gpt3.NewClient(apiKey)
		// client.Engine(ctx, gpt3.TextDavinci003Engine)

		question := "Explain, in an executive summary format using paragraphs, the following vulnerabilities: " + strings.Join(issuesForExecSummary, ", ")

		fmt.Println("Request the following from ChatGPT: ", question)

		// resp, err := client.Completion(ctx, gpt3.CompletionRequest{
		// 	Prompt:      []string{question},
		// 	MaxTokens:   gpt3.IntPtr(1000),
		// 	Temperature: gpt3.Float32Ptr(0),
		// 	Stop:        []string{"\r\n\r\n"},
		// })

		// if err != nil {
		// 	log.Println(err)
		// }

		// fmt.Println(resp.Choices[0].Text)
	}
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
