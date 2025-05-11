package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func getVaultMetricsURL() string {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200" // default fallback
	}
	return vaultAddr + "/v1/sys/metrics?format=prometheus"
}

func getLLMAPIURL() string {
	llmURL := os.Getenv("LLM_URL")
	if llmURL == "" {
		fmt.Fprintln(os.Stderr, "LLM_URL environment variable not set")
		os.Exit(1)
	}
	return llmURL
}

func fetchVaultMetrics() ([]byte, error) {
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		return nil, fmt.Errorf("VAULT_TOKEN environment variable not set")
	}

	req, err := http.NewRequest("GET", getVaultMetricsURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", vaultToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func filterNaNMetrics(metrics []byte) []byte {
	lines := bytes.Split(metrics, []byte("\n"))
	var filtered [][]byte
	for _, line := range lines {
		if !bytes.Contains(line, []byte("NaN")) {
			filtered = append(filtered, line)
		}
	}
	return bytes.Join(filtered, []byte("\n"))
}

func analyzeWithLLM(metrics, logs []byte) (string, error) {
	llmPrompt := fmt.Sprintf(`Analyze the following Vault server metrics for a human reader.
- Summarize the overall health and status in clear, simple language.
- Highlight any anomalies, errors, or warnings.
- Suggest possible causes and recommended actions if issues are found.
- Make the summary concise, actionable, and easy to understand for someone without deep technical knowledge.

Metrics:
%s`, string(metrics))
	payload := map[string]interface{}{
		"model":      "qwen2.5-32b-instruct",
		"prompt":     llmPrompt,
		"max_tokens": 20000,
		"metadata": map[string]string{
			"trace_name": "team_bot",
		},
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", getLLMAPIURL(), bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	llmToken := os.Getenv("LLM_TOKEN")
	if llmToken == "" {
		return "", fmt.Errorf("LLM_TOKEN environment variable not set")
	}
	req.Header.Set("Authorization", "Bearer "+llmToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	result, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("LLM API error: %s\n%s", resp.Status, string(result))
	}

	// Try to parse the response as JSON and extract the summary text
	var llmResp struct {
		Choices []struct {
			Text string `json:"text"`
		} `json:"choices"`
		// fallback for other possible fields
		Result string `json:"result"`
	}
	err = json.Unmarshal(result, &llmResp)
	if err == nil {
		if len(llmResp.Choices) > 0 && llmResp.Choices[0].Text != "" {
			return llmResp.Choices[0].Text, nil
		}
		if llmResp.Result != "" {
			return llmResp.Result, nil
		}
	}
	// fallback: return raw response
	return string(result), nil
}

func main() {
	metrics, err := fetchVaultMetrics()
	fmt.Print("Fetching Vault metrics...\n")
	if err != nil {
		fmt.Println("Error fetching metrics:", err)
		os.Exit(1)
	}

	filteredMetrics := filterNaNMetrics(metrics)
	fmt.Println("len(filteredMetrics):", len(filteredMetrics))
	if len(filteredMetrics) > 5000 {
		// Split metrics into two halves by lines
		lines := bytes.Split(filteredMetrics, []byte("\n"))
		n := len(lines)
		mid := n / 2
		firstHalf := bytes.Join(lines[:mid], []byte("\n"))
		secondHalf := bytes.Join(lines[mid:], []byte("\n"))

		fmt.Print("analysis data for first half...\n")
		analysis1, err := analyzeWithLLM(firstHalf, nil)
		if err != nil {
			fmt.Println("Error analyzing first half with LLM:", err)
			os.Exit(1)
		}

		fmt.Print("analysis data for second half...\n")
		analysis2, err := analyzeWithLLM(secondHalf, nil)
		if err != nil {
			fmt.Println("Error analyzing second half with LLM:", err)
			os.Exit(1)
		}

		fmt.Println("LLM Analysis Result (First Half):")
		fmt.Println(analysis1)
		fmt.Println("\nLLM Analysis Result (Second Half):")
		fmt.Println(analysis2)
	} else {
		fmt.Print("analysis data for all metrics...\n")
		analysis, err := analyzeWithLLM(filteredMetrics, nil)
		if err != nil {
			fmt.Println("Error analyzing metrics with LLM:", err)
			os.Exit(1)
		}
		fmt.Println("LLM Analysis Result:")
		fmt.Println(analysis)
	}
}
