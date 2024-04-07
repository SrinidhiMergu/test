package main

import (
	"container/list"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	gin "github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"github.com/golang-jwt/jwt/v4"

	subscription_helper "vertica.com/vaas/OCP/subscription-handler-app/subscription_helper"
	"vertica.com/vaas/logging"
)

var (
	subscriptionHandlerQueue = list.New() // Create a in-memory shared message queue for storing events
	applicationNameInput     = []string{}
	bearerAuthHeaderExp      = regexp.MustCompile(`^\s*(?i)Bearer(?-i)(?:\s+)([[:alnum:]-._~+/]+=*)\s*$`)
)

func main() {
	logConfig := logging.DefaultLoggingConfig()
	logConfig.Format = logging.LogFormatJSON // TODO: use environment setting in deployment config
	logFile := logging.InitLogging(logConfig)
	logging.DefaultLogLevel()
	defer logFile.Close()

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Define the webhook endpoint
	router.POST("/webhook", HandleWebhook)

	slog.Info("Listening on :8080...")

	go EventHandlerQueue()

	err := router.Run(":8080")
	if err != nil {
		slog.Error("Error starting server...")
		os.Exit(1)
	}
}

// Match a valid authorization header field as defined in RFC 6750 section 2.1,
// slightly relaxed in that it does a case-insensitive match on Bearer and
// allows for some extra whitespace.
func BearerTokenFromAuthHeader(c *gin.Context) string {
	authHdrValue := c.GetHeader("Authorization")
	m := bearerAuthHeaderExp.FindStringSubmatch(authHdrValue)
	if m != nil && len(m[1]) > 0 {
		return m[1]
	}
	return ""
}

// Extract clientId from otds token without verifiaction
func extractUnverifiedClaims(tokenString string) (string, error) {
	if tokenString == "" {
		slog.Error("Authorization token is missing")
		return "", fmt.Errorf("Authorization token is missing")
	}
	var name string
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		name = fmt.Sprint(claims["cid"])
	}

	if name == "" {
		return "", fmt.Errorf("invalid token payload")
	}
	return name, nil
}

// Reads request body from webhook and enqueues it in queue
func HandleWebhook(c *gin.Context) {
	// Extract the bearer token from the request.
	rawToken := BearerTokenFromAuthHeader(c)

	cId, err := extractUnverifiedClaims(rawToken)
	if err != nil {
		slog.Error("Unable to fetch client id: " + err.Error())
	}
	if cId == "vaas-events" {
		// Read the raw JSON data from the request body
		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body", "details": err.Error()})
			return
		}

		slog.Info("Received request body")

		// Enqueue the JSON data
		subscriptionHandlerQueue.PushBack(string(body))

		c.JSON(http.StatusOK, gin.H{"message": "Event Payload received and enqueued in a queue"})
		slog.Info("Event Payload received and enqueued in a queue")
	}
}

// Handles message once enqueued in queue and publishes to topic
func EventHandlerQueue() {
	for {
		// Check if Queue is empty or not
		if subscriptionHandlerQueue.Len() > 0 {
			element := subscriptionHandlerQueue.Front()

			msg, ok := element.Value.(string)
			if !ok {
				slog.Error("Error: Invalid message")
				subscriptionHandlerQueue.Remove(element)
				slog.Info("Invalid event removed from queue")
				continue
			}

			var eventData subscription_helper.EventData
			// Unmarshal the raw JSON data into struct
			err := json.Unmarshal([]byte(msg), &eventData)
			if err != nil {
				slog.Error("Error: " + err.Error())
				subscriptionHandlerQueue.Remove(element)
				continue
			}
			eventType := eventData.Type

			eventPayload := SubscriptionHandler(msg, eventType)
			if eventPayload == "" {
				slog.Info("Invalid event removed from queue")
				subscriptionHandlerQueue.Remove(element)
				continue
			}

			slog.Info("Processed event payload")

			roleArn := os.Getenv("snsPublishRoleARN")
			roleSessionName := os.Getenv("roleSessionName")
			region := os.Getenv("region")
			if roleArn == "" || roleSessionName == "" || region == "" {
				slog.Error("Error while fetching sns role configuration from Helm chart")
			}

			snsHelper, err := subscription_helper.NewSNSHelper(roleArn, roleSessionName, region)
			if err != nil {
				slog.Error("Error creating SNS helper: " + err.Error())
				continue
			}

			topicName := os.Getenv("snsTopic")
			topicARN := os.Getenv("snsTopicARN")

			success, err := snsHelper.PublishToTopic(eventPayload, topicARN)
			if err != nil {
				slog.Error("Failed to publish message to topic " + topicName + ": " + err.Error())
				continue
			}

			if success {
				slog.Info("Message is successfully published to topic " + topicName)
				slog.Info("Message: " + eventPayload)
				subscriptionHandlerQueue.Remove(element)
			}
		}
	}
}

// Receives message and calls appropriate handler function
func SubscriptionHandler(rawData string, eventType string) (eventPayload string) {
	applicationNameInput = strings.Split(os.Getenv("applicationName"), ",")
	if len(applicationNameInput) == 0 {
		slog.Error("Error while fetching application name from Helm chart")
	}

	switch eventType {
	case "com.opentext.ot2.ets.create-tenant":
		eventPayload = HandleTenantCreated(rawData)
	case "com.opentext.ot2.ets.create-tenant-user":
		eventPayload = HandleTenantUserCreated(rawData)
	case "com.opentext.ot2.ets.create-subscription":
		eventPayload = HandleSubscriptionCreated(rawData, applicationNameInput)
	case "com.opentext.ot2.ets.create-subscription-sku":
		eventPayload = HandleSubscriptionSKUCreated(rawData)
	case "com.opentext.ot2.ets.delete-subscription":
		eventPayload = HandleSubscriptionDeleted(rawData, applicationNameInput)
	case "com.opentext.ot2.ets.create-subscription-user":
		eventPayload = HandleSubscriptionUserCreated(rawData, applicationNameInput)
	case "com.opentext.ot2.ets.create-subscription-user-role":
		eventPayload = HandleSubscriptionUserRoleCreated(rawData)
	case "com.opentext.ot2.ets.delete-subscription-user-role":
		eventPayload = HandleSubscriptionUserRoleDeleted(rawData)
	case "com.opentext.ot2.ets.delete-subscription-user":
		eventPayload = HandleSubscriptionUserDeleted(rawData, applicationNameInput)
	default:
		slog.Info("Unknown event type: " + eventType)
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}
	return eventPayload
}

func HandleTenantCreated(rawData string) string {
	slog.Info("Handling TENANT_CREATED event")

	var eventData subscription_helper.TenantCreatedEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	err = validator.New().Struct(eventData)
	if err != nil {
		slog.Error("Validation failed due to: %s", err)
		return ""
	}

	tenantId := eventData.Tenant.ID
	tenantName := eventData.Tenant.CompanyName
	slog.Info("Received Tenant " + tenantName + " with tenantId " + tenantId)

	// Marshal the eventData back to a JSON string
	message, err := json.Marshal(eventData)
	if err != nil {
		slog.Error("Error marshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	return string(message)
}

func HandleTenantUserCreated(rawData string) string {
	slog.Info("Handling TENANT_USER_CREATED event")

	var eventData subscription_helper.TenantUserEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	tenantId := eventData.TenantUser.ID
	email := eventData.TenantUser.Email
	slog.Info("Received user " + email + " in tenant " + tenantId)

	// Marshal the eventData back to a JSON string
	message, err := json.Marshal(eventData)
	if err != nil {
		slog.Error("Error marshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	err = validator.New().Struct(eventData)
	if err != nil {
		slog.Error("Validation failed due to: %s", err)
		return ""
	}

	return string(message)
}

func HandleSubscriptionCreated(rawData string, applicationNameInput []string) string {
	slog.Info("Handling SUBSCRIPTION_CREATED event")

	var eventData subscription_helper.SubscriptionEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	for _, appNameVal := range applicationNameInput {
		// slog.Info("Inside for condition " + appNameVal)
		if appNameVal == eventData.Subscription.ApplicationName {
			// slog.Info("Inside if condition " + appNameVal)
			// slog.Info("Inside if condition in eventData " + eventData.Subscription.ApplicationName)
			subscriptionName := eventData.Subscription.Name
			subscriptionId := eventData.Subscription.ID
			tenantName := eventData.Subscription.Tenant.CompanyName
			tenantId := eventData.Subscription.Tenant.ID
			slog.Info("Received subscription " + subscriptionName + " with id " + subscriptionId + " in tenant " + tenantName + " with id " + tenantId)

			// Marshal the eventData back to a JSON string
			message, err := json.Marshal(eventData)
			if err != nil {
				slog.Error("Error marshaling JSON: " + err.Error())
				element := subscriptionHandlerQueue.Front()
				subscriptionHandlerQueue.Remove(element)
				return ""
			}

			err = validator.New().Struct(eventData)
			if err != nil {
				slog.Error("Validation failed due to: %s", err)
				return ""
			}
			return string(message)
		}
	}
	return ""
}

func HandleSubscriptionSKUCreated(rawData string) string {
	slog.Info("Handling SUBSCRIPTION_SKU_CREATED event")

	var eventData subscription_helper.SubscriptionSKUEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	skuName := eventData.SubscriptionSKU.Name
	subscriptionId := eventData.SubscriptionSKU.SubscriptionID
	slog.Info("Received subscription SKU " + skuName + " with subscription id " + subscriptionId)

	// Marshal the eventData back to a JSON string
	message, err := json.Marshal(eventData)
	if err != nil {
		slog.Error("Error marshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	err = validator.New().Struct(eventData)
	if err != nil {
		slog.Error("Validation failed due to: %s", err)
		return ""
	}
	return string(message)
}

func HandleSubscriptionDeleted(rawData string, applicationNameInput []string) string {
	slog.Info("Handling SUBSCRIPTION_DELETED event")

	var eventData subscription_helper.SubscriptionDeleteEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	for _, appNameVal := range applicationNameInput {
		if appNameVal == eventData.Subscription.ApplicationName {
			subscriptionName := eventData.Subscription.Name
			subscriptionId := eventData.Subscription.ID
			tenantName := eventData.Subscription.Tenant.CompanyName
			tenantId := eventData.Subscription.Tenant.ID
			slog.Info("Received deleted subscription " + subscriptionName + " with id " + subscriptionId + " in tenant " + tenantName + " with id " + tenantId)

			// Marshal the eventData back to a JSON string
			message, err := json.Marshal(eventData)
			if err != nil {
				slog.Error("Error marshaling JSON: " + err.Error())
				element := subscriptionHandlerQueue.Front()
				subscriptionHandlerQueue.Remove(element)
				return ""
			}

			err = validator.New().Struct(eventData)
			if err != nil {
				slog.Error("Validation failed due to: %s", err)
				return ""
			}
			return string(message)
		}
	}
	return ""
}

func HandleSubscriptionUserCreated(rawData string, applicationNameInput []string) string {
	slog.Info("Handling SUBSCRIPTION_USER_CREATED event")

	var eventData subscription_helper.SubscriptionUserCreatedEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	for _, appNameVal := range applicationNameInput {
		if appNameVal == eventData.SubscriptionUser.ApplicationName {
			subscriptionId := eventData.SubscriptionUser.SubscriptionID
			userEmail := eventData.SubscriptionUser.Email
			tenantId := eventData.SubscriptionUser.TenantID
			slog.Info("Received user with " + userEmail + " for subscription " + subscriptionId + " in tenant " + tenantId)

			// Marshal the eventData back to a JSON string
			message, err := json.Marshal(eventData)
			if err != nil {
				slog.Error("Error marshaling JSON: " + err.Error())
				element := subscriptionHandlerQueue.Front()
				subscriptionHandlerQueue.Remove(element)
				return ""
			}

			err = validator.New().Struct(eventData)
			if err != nil {
				slog.Error("Validation failed due to: %s", err)
				return ""
			}
			return string(message)
		}
	}
	return ""
}

func HandleSubscriptionUserRoleCreated(rawData string) string {
	slog.Info("Handling SUBSCRIPTION_USER_ROLE_CREATED event")

	var eventData subscription_helper.SubscriptionUserRoleCreatedEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	roleName := eventData.SubscriptionUserRole.RoleName
	subscriptionId := eventData.SubscriptionUserRole.SubscriptionID
	tenantId := eventData.SubscriptionUserRole.TenantID
	slog.Info("Received user role " + roleName + " for subscription " + subscriptionId + " in tenant " + tenantId)

	// Marshal the eventData back to a JSON string
	message, err := json.Marshal(eventData)
	if err != nil {
		slog.Error("Error marshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	err = validator.New().Struct(eventData)
	if err != nil {
		slog.Error("Validation failed due to: %s", err)
		return ""
	}
	return string(message)
}

func HandleSubscriptionUserRoleDeleted(rawData string) string {
	slog.Info("Handling SUBSCRIPTION_USER_ROLE_DELETED event")

	var eventData subscription_helper.SubscriptionUserRoleDeletedEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	err = validator.New().Struct(eventData)
	if err != nil {
		slog.Error("Validation failed due to: %s", err)
	}

	roleName := eventData.SubscriptionUserRole.RoleName
	subscriptionId := eventData.SubscriptionUserRole.SubscriptionID
	tenantId := eventData.SubscriptionUserRole.TenantID
	slog.Info("Received user role " + roleName + " for subscription " + subscriptionId + " in tenant " + tenantId)

	// Marshal the eventData back to a JSON string
	message, err := json.Marshal(eventData)
	if err != nil {
		slog.Error("Error marshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	err = validator.New().Struct(eventData)
	if err != nil {
		slog.Error("Validation failed due to: %s", err)
		return ""
	}
	return string(message)
}

func HandleSubscriptionUserDeleted(rawData string, applicationNameInput []string) string {
	slog.Info("Handling SUBSCRIPTION_USER_DELETED event")

	var eventData subscription_helper.SubscriptionUserDeletedEvent

	// Unmarshal the raw JSON data into the struct
	if err := json.Unmarshal([]byte(rawData), &eventData); err != nil {
		slog.Error("Error unmarshaling JSON: " + err.Error())
		element := subscriptionHandlerQueue.Front()
		subscriptionHandlerQueue.Remove(element)
		return ""
	}

	err = validator.New().Struct(eventData)
	if err != nil {
		slog.Error("Validation failed due to: %s", err)
	}

	for _, appNameVal := range applicationNameInput {
		if appNameVal == eventData.SubscriptionUser.ApplicationName {
			subscriptionId := eventData.SubscriptionUser.SubscriptionID
			userEmail := eventData.SubscriptionUser.Email
			tenantId := eventData.SubscriptionUser.TenantID
			slog.Info("Received deleted user with " + userEmail + " for subscription " + subscriptionId + " in tenant " + tenantId)

			// Marshal the eventData back to a JSON string
			message, err := json.Marshal(eventData)
			if err != nil {
				slog.Error("Error marshaling JSON: " + err.Error())
				element := subscriptionHandlerQueue.Front()
				subscriptionHandlerQueue.Remove(element)
				return ""
			}

			err = validator.New().Struct(eventData)
			if err != nil {
				slog.Error("Validation failed due to: %s", err)
				return ""
			}
			return string(message)
		}
	}
	return ""
}
