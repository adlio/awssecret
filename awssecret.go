package awssecret

import (
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
)

type dsn struct {
	Engine               string `json:"engine"`
	Host                 string `json:"host"`
	DBName               string `json:"dbname"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	Port                 int    `json:"port"`
	SearchPath           string `json:"search_path"`
	DBInstanceIdentifier string `json:"dbInstanceIdentifier"`
}

// GetPostgresDSNSecret retrieves the named secret from AWS Secrets Manager
// and converts it from the JSON its natively stored as into a Postgres-compatible
// DSN string
//
func GetPostgresDSNSecret(sess *session.Session, secretName string) (dsnStr string, err error) {
	str, err := GetStringSecret(sess, secretName)
	if err != nil {
		return "", errors.Wrapf(err, "Couldn't build DSN. Failed to retrieve secret")
	}

	// If the string already looks like a DSN, just return it
	if strings.Index(str, "host=") >= 0 && strings.Index(str, "dbname=") >= 0 {
		return str, nil
	}

	d := dsn{}
	err = json.Unmarshal([]byte(str), &d)
	if err != nil {
		return str, err
	}

	s := strings.Builder{}
	if d.Host != "" {
		s.WriteString("host=")
		s.WriteString(d.Host)
		s.WriteString(" ")
	}

	if d.DBName != "" {
		s.WriteString("dbname=")
		s.WriteString(d.DBName)
		s.WriteString(" ")
	}

	if d.Username != "" {
		s.WriteString("user=")
		s.WriteString(d.Username)
		s.WriteString(" ")
	}

	if d.Password != "" {
		s.WriteString("password=")
		s.WriteString(d.Password)
		s.WriteString(" ")
	}

	if d.SearchPath != "" {
		s.WriteString("search_path=")
		s.WriteString(d.SearchPath)
		s.WriteString(" ")
	}

	return s.String(), nil
}

// GetStringSecret retrieves the named secret from AWS Secrets Manager and
// returns it in its raw form
//
func GetStringSecret(sess *session.Session, secretName string) (secret string, err error) {

	//Create a Secrets Manager client if one wasn't passed in
	if sess == nil {
		sess = session.New()
	}

	svc := secretsmanager.New(sess)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	// In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
	// See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return "", errors.Wrapf(err, "Failed to get secret from AWS Secrets Manager: %s", aerr.Code())
		}
		return "", errors.Wrapf(err, "Fasiled to get secret from AWS Secrets Manager: Unknown error description")
	}

	if result.SecretString != nil {
		secret = *result.SecretString
		return secret, nil
	}

	return "", errors.New("Secret is not a string")
}
