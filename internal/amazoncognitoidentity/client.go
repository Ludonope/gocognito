package amazoncognitoidentity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Client store client informations
type Client struct {
	endpoint string
}

// NewClient returns a new client
func NewClient(region string, endpoint *string) *Client {
	var client Client

	if endpoint != nil {
		client.endpoint = *endpoint
	} else {
		client.endpoint = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/", region)
		req, _ := http.NewRequest("OPTIONS", client.endpoint, new(bytes.Buffer))
		httpClient := &http.Client{}
		httpClient.Do(req)
	}

	return &client
}

// Request execute a request
func (client *Client) Request(operation string, params interface{}) []byte {
	body, _ := json.Marshal(params)
	req, _ := http.NewRequest("POST", client.endpoint, bytes.NewBuffer(body))
	headers := map[string]string{
		"accept":           "*/*",
		"accept-encoding":  "gzip, deflate, br",
		"accept-language":  "en-US,en;q=0.9,fr;q=0.8",
		"cache-control":    "max-age=0",
		"content-type":     "application/x-amz-json-1.1",
		"connection":       "keep-alive",
		"dnt":              "1",
		"origin":           "http://localhost:8080",
		"referer":          "http://localhost:8080/login",
		"x-amz-target":     "AWSCognitoIdentityProviderService." + operation,
		"x-amz-user-agent": "aws-amplify/0.1.x js",
	}

	for key, val := range headers {
		req.Header.Set(key, val)
	}
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ = ioutil.ReadAll(resp.Body)
	return body
}
