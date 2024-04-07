package subscription_helper

import (
	"fmt"
	"context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// SNSHelper provides functions for working with SNS
type SNSHelper struct {
	cfg aws.Config
}

// NewSNSHelper creates a new SNSHelper instance with assumed role
func NewSNSHelper(roleArn string, roleSessionName string, region string) (*SNSHelper, error) {
	// Fetch Google Web Identity Token
	gToken, err := getWebIdentityToken()
	if err != nil {
		return nil, fmt.Errorf("Unable to fetch Google Web Identity Token: %s", err)
	}

	// Assume AWS role with the Google Web Identity Token
	tempCreds, err := getAWSCredentials(roleArn, roleSessionName, gToken)
	if err != nil {
		return nil, fmt.Errorf("failed to assume AWS Role: %s", err)
	}

	// Configure SNS client with assumed role credentials
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			*tempCreds.Credentials.AccessKeyId,
			*tempCreds.Credentials.SecretAccessKey,
			*tempCreds.Credentials.SessionToken,
		)),
		config.WithRegion(region),
	)
	// cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to configure SNS client: %s", err)
	}

	return &SNSHelper{cfg: cfg}, nil
}

func getWebIdentityToken() (string, error) {
	url := "http://sts.amazonaws.com"
 
	ctx := context.Background()
 
	// Construct the GoogleCredentials object which obtains the default configuration from your
	// working environment.
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to generate default credentials: %w", err)
	}
 
	ts, err := idtoken.NewTokenSource(ctx, url, option.WithCredentials(credentials))
	if err != nil {
		return "", fmt.Errorf("failed to create NewTokenSource: %w", err)
	}
 
	// Get the ID token.
	// Once you've obtained the ID token, you can use it to make an authenticated call
	// to the target audience.
	gToken, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("failed to receive token: %w", err)
	}
	fmt.Printf("Generated ID token")
 
	return gToken.AccessToken, nil
}

// Helper function to assume AWS role with Google Web Identity Token
func getAWSCredentials(roleArn, roleSessionName, gtoken string) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	// Load the default AWS configuration
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"))
	if err != nil {
		return nil, fmt.Errorf("failed to load default AWS config: %v", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	tempCreds, err := stsClient.AssumeRoleWithWebIdentity(context.TODO(), &sts.AssumeRoleWithWebIdentityInput{
		RoleSessionName:  &roleSessionName,
		RoleArn:          &roleArn,
		WebIdentityToken: &gtoken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to assume AWS role: %s", err)
	}
	return tempCreds, nil
}

// PublishToTopic publishes a message to an Amazon SNS topic.
func (s *SNSHelper) PublishToTopic(message string, topicARN string) (bool, error) {
	// create SNS Client
	sns_client := sns.NewFromConfig(s.cfg)

	// MYTOPICARN := "arn:aws:sns:us-east-2:821715312548:vaas-ocp-aws-topic"
	req := &sns.PublishInput{
        TopicArn: aws.String(topicARN),
        Message: aws.String(message),
    }

	_, err := sns_client.Publish(context.TODO(), req)
	if err != nil {
		return false, fmt.Errorf("Error while publishing message to topic: %s", err)
	}

	return true, nil
}
