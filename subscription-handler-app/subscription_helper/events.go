package subscription_helper

import (
	"time"
)

// To add custom methods or behavior to the time.Time type
type CustomTime struct {
	time.Time
}

func (ct *CustomTime) UnmarshalJSON(b []byte) error {
	s := string(b)
	s = s[1 : len(s)-1] // Remove the quotes from the string
	t, err := time.Parse("2006-01-02 15:04:05.000", s)
	if err != nil {
		return err
	}
	ct.Time = t
	return nil
}

type EventData struct {
	Type      string      `json:"type"`
	RequestId string      `json:"requestid`
	Data      interface{} `json:"data"`
}

type TenantCreatedEvent struct {
	Tenant struct {
		CreatedBy        string     `json:"createdBy" validate:"required"`
		CreatedDate      CustomTime `json:"createdDate" validate:"required"`
		ModifiedBy       string     `json:"modifiedBy,omitempty"`
		ModifiedDate     CustomTime `json:"modifiedDate,omitempty"`
		ID               string     `json:"id" validate:"required"`
		CompanyName      string     `json:"companyName" validate:"required"`
		DisplayName      string     `json:"displayName"`
		Department       string     `json:"department"`
		CompanySize      string     `json:"companySize"`
		ContactEmail     string     `json:"contactEmail" validate:"email"`
		ContactFirstName string     `json:"contactFirstName"`
		ContactLastName  string     `json:"contactLastName"`
		Status           string     `json:"status"`
		OrganizationID   string     `json:"organizationId"`
		OrganizationName string     `json:"organizationName"`
		IdentityProvider string     `json:"identityProvider"`
	} `json:"data"`
	EventType string `json:"type"`
}

type TenantUserEvent struct {
	EventType  string `json:"type"`
	TenantUser struct {
		CreatedBy      string      `json:"createdBy" validate:"required"`
		CreatedDate    CustomTime  `json:"createdDate" validate:"required"`
		ModifiedBy     *string     `json:"modifiedBy" validate:"omitempty"`
		ModifiedDate   *CustomTime `json:"modifiedDate" validate:"omitempty"`
		ID             string      `json:"id" validate:"required"`
		OTDSUUID       string      `json:"otdsUuid"`
		FirstName      string      `json:"firstName"`
		LastName       *string     `json:"lastName"`
		Email          string      `json:"email" validate:"email"`
		TenantID       string      `json:"tenantId" validate:"required"`
		OTDSUserID     string      `json:"otdsUserId"`
		OTDSUserName   string      `json:"otdsUserName"`
		OAuth2ClientID *string     `json:"oauth2ClientId"`
		UserProfileID  string      `json:"userProfileId"`
		TenantAdmin    bool        `json:"tenantAdmin"`
	} `json:"data"`
}

type SubscriptionEvent struct {
	EventType    string `json:"type"`
	Subscription struct {
		CreatedBy              string      `json:"createdBy" validate:"required"`
		CreatedDate            CustomTime  `json:"createdDate" validate:"required"`
		ModifiedBy             *string     `json:"modifiedBy" validate:"omitempty"`
		ModifiedDate           *CustomTime `json:"modifiedDate" validate:"omitempty"`
		ID                     string      `json:"id" validate:"required"`
		ContactEmail           string      `json:"contactEmail" validate:"email"`
		ContactFirstName       *string     `json:"contactFirstName"`
		ContactLastName        *string     `json:"contactLastName"`
		Name                   string      `json:"name" validate:"required"`
		DisplayName            string      `json:"displayName"`
		SubscriptionURL        string      `json:"subscriptionUrl"`
		Status                 string      `json:"status"`
		Type                   string      `json:"type"`
		ApplicationName        string      `json:"applicationName" validate:"required"`
		ApplicationDisplayName string      `json:"applicationDisplayName"`
		ApplicationVersion     string      `json:"applicationVersion"`
		ApplicationID          string      `json:"applicationId"`
		EffectiveDate          CustomTime  `json:"effectiveDate"`
		ExpiryDate             CustomTime  `json:"expiryDate"`
		Tenant                 struct {
			ID          string `json:"id" validate:"required"`
			CompanyName string `json:"companyName" validate:"required"`
		} `json:"tenant"`
	} `json:"data"`
}

type SubscriptionSKUEvent struct {
	EventType       string `json:"type"`
	SubscriptionSKU struct {
		CreatedBy      string      `json:"createdBy" validate:"required"`
		CreatedDate    CustomTime  `json:"createdDate" validate:"required"`
		ModifiedBy     *string     `json:"modifiedBy"`
		ModifiedDate   *CustomTime `json:"modifiedDate"`
		ID             string      `json:"id" validate:"required"`
		Name           string      `json:"name" validate:"required"`
		Description    *string     `json:"description"`
		EffectiveDate  CustomTime  `json:"effectiveDate"`
		ExpiryDate     CustomTime  `json:"expiryDate"`
		LastResetDate  *CustomTime `json:"lastResetDate"`
		SubscriptionID string      `json:"subscriptionId" validate:"required"`
		Expired        bool        `json:"expired"`
	} `json:"data"`
}

type SubscriptionDeleteEvent struct {
	EventType    string `json:"type"`
	Subscription struct {
		CreatedBy              string      `json:"createdBy" validate:"required"`
		CreatedDate            CustomTime  `json:"createdDate" validate:"required"`
		ModifiedBy             *string     `json:"modifiedBy"`
		ModifiedDate           *CustomTime `json:"modifiedDate"`
		ID                     string      `json:"id" validate:"required"`
		ContactEmail           string      `json:"contactEmail" validate:"email"`
		Name                   string      `json:"name"`
		DisplayName            string      `json:"displayName"`
		SubscriptionURL        string      `json:"subscriptionUrl"`
		Status                 string      `json:"status"`
		Type                   string      `json:"type"`
		ApplicationName        string      `json:"applicationName"`
		ApplicationDisplayName string      `json:"applicationDisplayName"`
		ApplicationVersion     string      `json:"applicationVersion"`
		ApplicationID          string      `json:"applicationId"`
		EffectiveDate          CustomTime  `json:"effectiveDate"`
		ExpiryDate             CustomTime  `json:"expiryDate"`
		Tenant                 struct {
			ID          string `json:"id"`
			CompanyName string `json:"companyName"`
		} `json:"tenant"`
	} `json:"data"`
}

type SubscriptionUserCreatedEvent struct {
	EventType        string `json:"type"`
	SubscriptionUser struct {
		CreatedBy               string      `json:"createdBy" validate:"required"`
		CreatedDate             CustomTime  `json:"createdDate" validate:"required"`
		ModifiedBy              *string     `json:"modifiedBy"`
		ModifiedDate            *CustomTime `json:"modifiedDate"`
		ID                      string      `json:"id" validate:"required"`
		OTDSUUID                string      `json:"otdsUuid"`
		FirstName               *string     `json:"firstName"`
		LastName                *string     `json:"lastName"`
		Email                   string      `json:"email" validate:"email"`
		Status                  string      `json:"status"`
		TenantID                string      `json:"tenantId" validate:"required"`
		PartitionID             string      `json:"partitionId"`
		OTDSUserID              string      `json:"otdsUserId"`
		OTDSUserName            string      `json:"otdsUserName"`
		UserProfileID           string      `json:"userProfileId"`
		SubscriptionID          string      `json:"subscriptionId" validate:"required"`
		ApplicationName         string      `json:"applicationName" validate:"required"`
		SubscriptionName        string      `json:"subscriptionName"`
		ApplicationDisplayName  string      `json:"applicationDisplayName"`
		SubscriptionDisplayName string      `json:"subscriptionDisplayName"`
	} `json:"data"`
}

type SubscriptionUserRoleCreatedEvent struct {
	EventType            string `json:"type"`
	SubscriptionUserRole struct {
		CreatedBy               string      `json:"createdBy" validate:"required"`
		CreatedDate             CustomTime  `json:"createdDate" validate:"required"`
		ModifiedBy              *string     `json:"modifiedBy"`
		ModifiedDate            *CustomTime `json:"modifiedDate"`
		ID                      string      `json:"id" validate:"required"`
		RoleName                string      `json:"roleName"`
		RoleDescription         string      `json:"roleDescription"`
		SubscriptionID          string      `json:"subscriptionId" validate:"required"`
		TenantID                string      `json:"tenantId" validate:"required"`
		RoleID                  string      `json:"roleId"`
		UserProfileID           string      `json:"userProfileId"`
		UserProfileEmail        string      `json:"userProfileEmail"`
		UserProfileOTDSUserID   string      `json:"userProfileOtdsUserId"`
		UserProfileOTDSUserName string      `json:"userProfileOtdsUserName"`
	} `json:"data"`
}

type SubscriptionUserRoleDeletedEvent struct {
	EventType            string `json:"type"`
	SubscriptionUserRole struct {
		CreatedBy               string      `json:"createdBy" validate:"required"`
		CreatedDate             CustomTime  `json:"createdDate" validate:"required"`
		ModifiedBy              *string     `json:"modifiedBy"`
		ModifiedDate            *CustomTime `json:"modifiedDate"`
		ID                      string      `json:"id" validate:"required"`
		RoleName                string      `json:"roleName"`
		RoleDescription         string      `json:"roleDescription"`
		SubscriptionID          string      `json:"subscriptionId" validate:"required"`
		TenantID                string      `json:"tenantId" validate:"required"`
		RoleID                  string      `json:"roleId"`
		UserProfileID           string      `json:"userProfileId"`
		UserProfileEmail        string      `json:"userProfileEmail"`
		UserProfileOTDSUserID   string      `json:"userProfileOtdsUserId"`
		UserProfileOTDSUserName string      `json:"userProfileOtdsUserName"`
	} `json:"data"`
}

type SubscriptionUserDeletedEvent struct {
	EventType        string `json:"type"`
	SubscriptionUser struct {
		CreatedBy               string      `json:"createdBy" validate:"required"`
		CreatedDate             CustomTime  `json:"createdDate" validate:"required"`
		ModifiedBy              *string     `json:"modifiedBy"`
		ModifiedDate            *CustomTime `json:"modifiedDate"`
		ID                      string      `json:"id" validate:"required"`
		OTDSUUID                string      `json:"otdsUuid"`
		FirstName               *string     `json:"firstName"`
		LastName                *string     `json:"lastName"`
		Email                   string      `json:"email" validate:"email"`
		Status                  string      `json:"status"`
		TenantID                string      `json:"tenantId" validate:"required"`
		PartitionID             string      `json:"partitionId"`
		OTDSUserID              string      `json:"otdsUserId"`
		OTDSUserName            string      `json:"otdsUserName"`
		UserProfileID           string      `json:"userProfileId"`
		SubscriptionID          string      `json:"subscriptionId" validate:"required"`
		ApplicationName         string      `json:"applicationName"`
		SubscriptionName        string      `json:"subscriptionName" validate:"required"`
		ApplicationDisplayName  string      `json:"applicationDisplayName"`
		SubscriptionDisplayName string      `json:"subscriptionDisplayName"`
	} `json:"data"`
}
