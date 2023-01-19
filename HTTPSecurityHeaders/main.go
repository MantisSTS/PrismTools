package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
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

type AddHeaders struct {
	LastUpdateUTC string   `json:"last_update_utc"`
	Headers       []Header `json:"headers"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RemoveHeaders struct {
	LastUpdateUTC string   `json:"last_update_utc"`
	Headers       []string `json:"headers"`
}

var (
	resultsQueue    = make(chan string, 100)
	jobQueue        = make(chan string, 100)
	headersToAdd    AddHeaders
	headersToRemove RemoveHeaders
)

func fetchAddHeaders() {
	url := "https://owasp.org/www-project-secure-headers/ci/headers_add.json"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("NewRequest: ", err)
		return
	}

	// Parse the JSON
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal("Do: ", err)
		return
	}

	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != 200 {
		log.Fatalf("Status code error: %d %s", resp.StatusCode, resp.Status)
	}

	// Decode the JSON
	var addHeaders AddHeaders
	if err := json.NewDecoder(resp.Body).Decode(&addHeaders); err != nil {
		log.Println(err)
	}

	headersToAdd = addHeaders
}

func fetchRemoveHeaders() {
	url := "https://owasp.org/www-project-secure-headers/ci/headers_remove.json"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("NewRequest: ", err)
		return
	}

	// Parse the JSON
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal("Do: ", err)
		return
	}

	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != 200 {
		log.Fatalf("Status code error: %d %s", resp.StatusCode, resp.Status)
	}

	// Decode the JSON
	var removeHeaders RemoveHeaders
	if err := json.NewDecoder(resp.Body).Decode(&removeHeaders); err != nil {
		log.Println(err)
	}

	headersToRemove = removeHeaders
}

func checkHeaders(url string) {

	// Ignore SSL certificates
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// Create a new request using http
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		log.Fatal("NewRequest: ", err)
		return
	}

	// Check the headers in the response
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal("Do: ", err)
		return
	}

	defer resp.Body.Close()

	// Check the headers
	for headerName, headerValue := range resp.Header {
		for _, OSHPHeader := range headersToAdd.Headers {
			if strings.EqualFold(strings.ToLower(strings.ReplaceAll(headerName, " ", "")), strings.ToLower(strings.ReplaceAll(OSHPHeader.Name, " ", ""))) {
				if headerValue[0] != OSHPHeader.Value {
					fmt.Printf("URL: %s | Header %s is not set to %s", url, headerName, OSHPHeader.Value)
				}
			}
		}
	}

	// Push the results to the queue
	// resultsQueue <- fmt.Sprintf("%s: %s", url, resp.Status)
}

func processQueue(jobQueue chan string, wg *sync.WaitGroup) {

	// Loop over the queue
	for url := range jobQueue {
		checkHeaders(url)
	}
	wg.Done()
}

func parseToPrism(data []byte) Prism {
	var prism Prism
	err := json.Unmarshal(data, &prism)
	if err != nil {
		log.Fatal(err)
	}
	return prism
}

func main() {
	threads := flag.Int("t", 10, "Number of threads to use")
	outputFile := flag.String("o", "output.txt", "Output file")
	flag.Parse()

	if *outputFile == "" {
		log.Fatal("No output file specified")
	}

	fetchAddHeaders()
	fetchRemoveHeaders()

	// Create a wait group
	var wg sync.WaitGroup

	sc := bufio.NewScanner(os.Stdin)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for sc.Scan() {
			jobQueue <- strings.TrimSpace(sc.Text())
		}
		close(jobQueue)
	}()

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go processQueue(jobQueue, &wg)
	}

	// // Create a file
	// f, err := os.Create(*outputFile)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer f.Close()

	// // Write the results to the file
	// for i := 0; i < cap(jobQueue); i++ {
	// 	f.WriteString(<-resultsQueue)
	// }

	wg.Wait()

	close(resultsQueue)

	for res := range resultsQueue {
		fmt.Println(res)
	}

}
