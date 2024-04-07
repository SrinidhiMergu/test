package main

import (
	"bytes"
	"container/list"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	gin "github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	subscription_helper "vertica.com/vaas/OCP/subscription-handler-app/subscription_helper"
)

var ApplicatioName = []string{}

// Mock SNSHelper
type MockSNSHelper struct{}

func (m *MockSNSHelper) PublishToTopic(message string, topicName string) (bool, error) {
	// Simulate successful publication to topic
	return true, nil
}

type MockTokenExtractor struct {
	mock.Mock
}

func (m *MockTokenExtractor) BearerTokenFromAuthHeader(c *gin.Context) string {
	args := m.Called(c)
	return args.String(0)
}

type MockClaimsExtractor struct {
	mock.Mock
}

func (m *MockClaimsExtractor) extractUnverifiedClaims(tokenString string) (string, error) {
	args := m.Called(tokenString)
	return args.String(0), args.Error(1)
}

func TestBearerTokenFromAuthHeader(t *testing.T) {
	c := &gin.Context{
		Request: &http.Request{
			Header: http.Header{"Authorization": []string{"Bearer abc123"}},
		},
	}
	token := BearerTokenFromAuthHeader(c)
	assert.Equal(t, "abc123", token)
}

func TestExtractUnverifiedClaims(t *testing.T) {
	// Test with empty token string
	name, err := extractUnverifiedClaims("")
	assert.NotNil(t, err)
	assert.Equal(t, "Authorization token is missing", err.Error())
	assert.Equal(t, "", name)

	// Test with valid token
	claims := jwt.MapClaims{
		"cid": "vaas-events",
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))
	name, err = extractUnverifiedClaims(tokenString)
	assert.Nil(t, err)
	assert.Equal(t, "vaas-events", name)
}

func TestHandleWebhook(t *testing.T) {
	// Mock token extractor
	tokenExtractorMock := new(MockTokenExtractor)
	tokenExtractorMock.On("BearerTokenFromAuthHeader", mock.Anything).Return("mocked-token")

	// Mock claims extractor
	claimsExtractorMock := new(MockClaimsExtractor)
	claimsExtractorMock.On("extractUnverifiedClaims", "mocked-token").Return("vaas-events", nil)

	handler := func(c *gin.Context) {
		rawToken := tokenExtractorMock.BearerTokenFromAuthHeader(c)

		cId, err := claimsExtractorMock.extractUnverifiedClaims(rawToken)
		if err != nil {
			t.Errorf("Unable to fetch client id: " + err.Error())
		}

		if cId == "vaas-events" {
			c.JSON(http.StatusOK, gin.H{"message": "Event Payload received and enqueued in a queue"})
		}
	}
	// Mock the gin context
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/webhook", handler)

	// Prepare the request body
	requestBody := bytes.NewBuffer([]byte(`{"key": "value"}`))

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/webhook", requestBody)
	assert.Nil(t, err)

	// Set authorization header
	req.Header.Set("Authorization", "Bearer abc123")

	// Create a response recorder to record the response
	w := httptest.NewRecorder()

	// Serve the HTTP request
	router.ServeHTTP(w, req)

	// Check the status code of the response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d but got %d", http.StatusOK, w.Code)
	}

	// Assert that the response body contains the expected message, ignoring whitespace differences
	assert.JSONEq(t, `{"message": "Event Payload received and enqueued in a queue"}`, w.Body.String())
}

func TestEventHandlerQueue(t *testing.T) {
	// Set up a mock SNSHelper
	snsHelper := &MockSNSHelper{}

	// Mocked message for testing
	msg := `{"type": "test_event"}`

	// Enqueue the message manually
	queue := list.New()
	queue.PushBack(msg)

	// Execute EventHandlerQueue in a separate goroutine
	go MockEventHandlerQueue(queue, snsHelper)

	// Wait for some time to let the EventHandlerQueue process the message
	time.Sleep(1 * time.Second)

	// Ensure that the queue is empty after processing the message
	assert.Equal(t, 0, queue.Len(), "Queue should be empty after processing the message")
}

// Handles message once enqueued in queue and publishes to topic
func MockEventHandlerQueue(queue *list.List, snsHelper *MockSNSHelper) {
	for {
		// Check if the queue is empty
		if queue.Len() == 0 {
			// If empty, sleep for some time and then check again
			time.Sleep(1 * time.Second)
			continue
		}

		// Retrieve the message from the front of the queue
		element := queue.Front()
		msg, ok := element.Value.(string)
		if !ok {
			// If the message is invalid, remove it from the queue and continue
			queue.Remove(element)
			continue
		}

		// Unmarshal the message into a map
		var jsonData map[string]interface{}
		err := json.Unmarshal([]byte(msg), &jsonData)
		if err != nil {
			// If unmarshaling fails, remove the message from the queue and continue
			queue.Remove(element)
			continue
		}

		// Extract the event type from the message
		_, ok = jsonData["type"].(string)
		if !ok {
			// If the event type is missing or invalid, remove the message from the queue and continue
			queue.Remove(element)
			continue
		}

		// Process the message based on the event type (not shown here)
		topicName := os.Getenv("snsTopic")
		// Publish the event payload to the topic using the SNSHelper
		success, err := snsHelper.PublishToTopic(msg, topicName)
		if err != nil {
			// If publishing fails, log an error
			continue
		}

		if success {
			// If publishing is successful, remove the message from the queue
			queue.Remove(element)
		}
	}
}

// TestHandleTenantCreated tests the HandleTenantCreated function
func TestHandleTenantCreated(t *testing.T) {
	// Define test data
	rawData := `{
        "data": {
            "createdBy": "25874eee-b736-4110-99b4-4882713e7c7a",
            "createdDate": "2024-01-08 04:56:35.400",
            "modifiedBy": null,
            "modifiedDate": null,
            "id": "396c03ba-750a-4252-87",
            "companyName": "vaas-mbir",
            "displayName": null,
            "department": null,
            "companySize": null,
            "contactEmail": "xyz@opentext.com",
            "contactFirstName": "xyz",
            "contactLastName": "",
            "status": "ACTIVE",
            "organizationId": "5fdd1f49-16cc-4b89-80bf",
            "organizationName": "opentextroot",
            "identityProvider": null
        },
        "type": "com.opentext.ot2.ets.create-tenant"
    }`

	// Call the function being tested
	result := HandleTenantCreated(rawData)

	// Unmarshal the result back into a struct
	var eventData subscription_helper.TenantCreatedEvent
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}

func TestHandleTenantUserCreated(t *testing.T) {
	// Define test data
	rawData := `{
        "data": {
            "createdBy": "25874eee-b736-4110-99b4-4882713e7c7a",
            "createdDate": "2024-01-08 04:56:36.527",
            "modifiedBy": null,
            "modifiedDate": null,
            "id": "349dc3ef-6d5e-4a32-8f59-f505bab9f973",
            "otdsUuid": "4d205aa0-8db9-452e-84b7-5d638c13d9e3",
            "firstName": "xyz",
            "lastName": "",
            "email": "xyz@opentext.com",    
            "tenantId": "396c03ba-750a-4252-80b3-e086c48f152d",    
            "otdsUserId": "xyz@opentext.com",
            "otdsUserName": "xyz@opentext.com",
            "oauth2ClientId": null,    
            "userProfileId": "a4e8312a-6ce1-4859-bb4d-5fc918398e92",        
            "tenantAdmin": true
        },
        "type": "com.opentext.ot2.ets.create-tenant-user"
    }`

	// Call the function being tested
	result := HandleTenantUserCreated(rawData)

	var eventData subscription_helper.TenantUserEvent

	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}

func TestHandleSubscriptionCreated(t *testing.T) {
	applicationNameInput = []string{"VaaS", "OTCAD"}
	// Define test data
	rawData := `{
        "type": "com.opentext.ot2.ets.create-subscription",
        "data": {
            "createdBy": "25874eee-b736-4110-99b4-4882713e7c7a",
            "createdDate": "2024-01-08 05:01:08.475",
            "modifiedBy": null,
            "modifiedDate": null,
            "id": "cff7ed41-1e4d-4d60-a809-caee325c87ce",
            "contactEmail": "xyz@opentext.com",
            "contactFirstName": null,
            "contactLastName": null,        
            "name": "vaas-1",
            "displayName": "vaas-1",
            "subscriptionUrl": "https://vaas.dev.ca.opentext.com/iportal?subscription-name=vaas-1",
            "status": "ACTIVE",
            "type": "PROD",
            "applicationName": "OTCAD",
            "applicationDisplayName": "Vertica As a Service",
            "applicationVersion": "1.0",        
            "applicationId": "d421ed0e-6b8c-47eb-928c-aedd6447e76a",
            "effectiveDate": "2024-01-08 00:00:00.000",
            "expiryDate": "2025-01-07 23:59:00.000",
            "tenant": {
                "id": "396c03ba-750a-4252-80b3-e086c48f152d",
                "companyName": "vaas"
            }
        }
    }`

	// Call the function being tested
	result := HandleSubscriptionCreated(rawData, applicationNameInput)

	var eventData subscription_helper.SubscriptionEvent

	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}

func TestHandleSubscriptionSKUCreated(t *testing.T) {
	// Define test data
	rawData := `{
       "data": {
            "createdBy": "25874eee-b736-4110-99b4-4882713e7c7a",
            "createdDate": "2024-01-17 06:03:59.599",
            "modifiedBy": null,
            "modifiedDate": null,
            "id": "c40c40ca-9dfa-4884-b449-1e6a2ffab9ca",
            "name": "d-1",
            "description": null,
            "effectiveDate": "2024-01-17 00:00:00.000",
            "expiryDate": "2025-01-16 23:59:00.000",
            "lastResetDate": null,
            "subscriptionId": "81898eb9-6b8a-41a9-a6c3-96f5fbefa47d",
            "expired": false
        },
        "type": "com.opentext.ot2.ets.create-subscription-sku"
    }`

	// Call the function being tested
	result := HandleSubscriptionSKUCreated(rawData)

	var eventData subscription_helper.SubscriptionSKUEvent

	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}

func TestHandleSubscriptionDeleted(t *testing.T) {
	applicationNameInput = []string{"VaaS", "OTCAD"}
	// Define test data
	rawData := `{
        "data": {
            "createdBy": "25874eee-b736-4110-99b4-4882713e7c7a",
            "createdDate": "2024-01-08 05:01:08.475",
            "modifiedBy": null,
            "modifiedDate": null,
            "id": "cff7ed41-1e4d-4d60-a809-caee325c87ce",
            "contactEmail": "xyz@opentext.com",        
            "name": "vaas-1",
            "displayName": "vaas-1",
            "subscriptionUrl": "https://vaas.dev.ca.opentext.com/iportal?subscription-name=vaas",
            "status": "ACTIVE",
            "type": "PROD",
            "applicationName": "OTCAD",
            "applicationDisplayName": "Vertica As a Service",
            "applicationVersion": "1.0",        
            "applicationId": "d421ed0e-6b8c-47eb-928c-aedd6447e76a",        
            "effectiveDate": "2024-01-08 00:00:00.000",
            "expiryDate": "2025-01-07 23:59:00.000",
            "tenant": {
                "id": "396c03ba-750a-4252-80b3-e086c48f152d",
                "companyName": "vaas"
            }
        },
        "type": "com.opentext.ot2.ets.delete-subscription"
    }`

	// Call the function being tested
	result := HandleSubscriptionDeleted(rawData, applicationNameInput)

	var eventData subscription_helper.SubscriptionDeleteEvent

	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}

func TestHandleSubscriptionUserCreated(t *testing.T) {
	applicationNameInput = []string{"VaaS", "OTCAD"}
	// Define test data
	rawData := `{
        "type": "com.opentext.ot2.ets.create-subscription-user",
        "data": {
            "createdBy": "943c60d0-5b48-4ad6-ba2c-ee0838a06546",
            "createdDate": "2024-01-05 11:11:43.674",
            "modifiedBy": null,
            "modifiedDate": null,
            "id": "3a8041f9-2945-4fbe-863e-795050054989",
            "otdsUuid": "e469897e-7e43-4dec-90e6-6ca76f51e06a",
            "firstName": null,
            "lastName": null,
            "email": "xyz@opentext.com",        
            "status": "ACTIVE",        
            "tenantId": "3485bc52-eb62-455f-be79-357bb00ef402",
            "partitionId": "3485bc52-eb62-455f-be79-357bb00ef402",        
            "otdsUserId": "xyz@opentext.com",
            "otdsUserName": "xyz@opentext.com",        
            "userProfileId": "25a286d5-ba3b-441a-894f-5c73ef5a867c",
            "subscriptionId": "6592d68e-6fa4-4d0d-a4b9-1c834d42d1f4",
            "applicationName": "OTCAD",
            "subscriptionName": "VaaSSubscription1",
            "applicationDisplayName": "Vertica As a Service",
            "subscriptionDisplayName": "VaaSSubscription1"    
        }
    }`

	// Call the function being tested
	result := HandleSubscriptionUserCreated(rawData, applicationNameInput)

	var eventData subscription_helper.SubscriptionUserCreatedEvent

	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}

func TestHandleSubscriptionUserRoleCreated(t *testing.T) {
	// Define test data
	rawData := `{
            "type": "com.opentext.ot2.ets.create-subscription-user-role",
            "data": {
                "createdBy": "a3c143e6-9e5f-4eb0-8b3e-52815c64364c",
                "createdDate": "2024-01-04 09:22:29.744",
                "modifiedBy": null,
                "modifiedDate": null,
                "id": "d1cd265e-5e3d-426c-8130-884aa29bd15e",
                "roleName": "Data Operator",
                "roleDescription": "Use the Data Warehouse feature to import source data from object storage",
                "subscriptionId": "c714be52-d4b3-4ee5-b309-41b6c0a56de6",
                "tenantId": "7629e806-516a-4c95-ae0f-e97f86292b07",
                "roleId": "bc0f0901-ee7b-4de1-8d4e-6edbd76e452f",
                "userProfileId": "517e637f-fb32-4d15-95e2-74fe39442d24",
                "userProfileEmail": "xyz@opentext.com",
                "userProfileOtdsUserId": "xyz@opentext.com",
                "userProfileOtdsUserName": "xyz@opentext.com"
            }
        }`

	// Call the function being tested
	result := HandleSubscriptionUserRoleCreated(rawData)

	var eventData subscription_helper.SubscriptionUserRoleCreatedEvent

	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}

func TestHandleSubscriptionUserRoleDeleted(t *testing.T) {
	// Define test data
	rawData := `{
            "type": "com.opentext.ot2.ets.delete-subscription-user-role",
            "data": {
                "createdBy": "a3c143e6-9e5f-4eb0-8b3e-52815c64364c",
                "createdDate": "2024-01-04 09:22:29.744",
                "modifiedBy": null,
                "modifiedDate": null,
                "id": "d1cd265e-5e3d-426c-8130-884aa29bd15e",
                "roleName": "Data Operator",
                "roleDescription": "Use the Data Warehouse feature to import source data from object storage",
                "subscriptionId": "c714be52-d4b3-4ee5-b309-41b6c0a56de6",
                "tenantId": "7629e806-516a-4c95-ae0f-e97f86292b07",
                "roleId": "bc0f0901-ee7b-4de1-8d4e-6edbd76e452f",
                "userProfileId": "517e637f-fb32-4d15-95e2-74fe39442d24",
                "userProfileEmail": "xyz@opentext.com",
                "userProfileOtdsUserId": "xyz@opentext.com",
                "userProfileOtdsUserName": "xyz@opentext.com"
            }
        }`

	// Call the function being tested
	result := HandleSubscriptionUserRoleDeleted(rawData)

	var eventData subscription_helper.SubscriptionUserRoleDeletedEvent

	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}

func TestHandleSubscriptionUserDeleted(t *testing.T) {
	applicationNameInput = []string{"VaaS", "OTCAD"}
	// Define test data
	rawData := `{
        "data": {
            "createdBy": "943c60d0-5b48-4ad6-ba2c-ee0838a06546",
            "createdDate": "2024-01-05 11:11:43.674",
            "modifiedBy": null,
            "modifiedDate": null,
            "id": "3a8041f9-2945-4fbe-863e-795050054989",
            "otdsUuid": "e469897e-7e43-4dec-90e6-6ca76f51e06a",
            "firstName": null,
            "lastName": null,
            "email": "abcd@opentext.com",        
            "status": "ACTIVE",        
            "tenantId": "3485bc52-eb62-455f-be79-357bb00ef402",
            "partitionId": "3485bc52-eb62-455f-be79-357bb00ef402",        
            "otdsUserId": "xyz@opentext.com",
            "otdsUserName": "xyz@opentext.com",        
            "userProfileId": "25a286d5-ba3b-441a-894f-5c73ef5a867c",
            "subscriptionId": "6592d68e-6fa4-4d0d-a4b9-1c834d42d1f4",
            "applicationName": "OTCAD",
            "subscriptionName": "VaaSSubscription1",
            "applicationDisplayName": "Vertica As a Service",
            "subscriptionDisplayName": "VaaSSubscription1"       
        },
        "type": "com.opentext.ot2.ets.delete-subscription-user"
    }`

	// Call the function being tested
	result := HandleSubscriptionUserDeleted(rawData, applicationNameInput)

	var eventData subscription_helper.SubscriptionUserDeletedEvent

	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		t.Errorf("Error unmarshaling JSON: %s", err)
	}

	// Marshal the eventData back to a JSON string
	expected, err := json.Marshal(eventData)
	if err != nil {
		t.Errorf("Error marshaling JSON: %s", err)
	}

	if result != string(expected) {
		t.Errorf("Expected: %v, got: %v", string(expected), result)
	}
}
