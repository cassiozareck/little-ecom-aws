package main

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"strconv"
)

// Secret struct to map MongoDB credentials
type MongoSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	DBName   string `json:"dbname"`
}

func setupMongoDB() {
	secretName := "MongoSM"
	region := "sa-east-1"

	// Load AWS configuration
	config, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Fatal(err)
	}

	// Create Secrets Manager client
	svc := secretsmanager.NewFromConfig(config)

	// Get secret value from Secrets Manager
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(context.TODO(), input)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Parse the secret JSON into the MongoSecret struct
	var secret MongoSecret
	if err := json.Unmarshal([]byte(*result.SecretString), &secret); err != nil {
		log.Fatalf("Failed to unmarshal secret string: %v", err)
	}

	// Build MongoDB URI
	mongoURI := "mongodb://" + secret.Username + ":" + secret.Password + "@" + secret.Host + ":" + strconv.Itoa(secret.Port) + "/" + secret.DBName

	// Set up MongoDB connection
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(mongoURI).SetServerAPIOptions(serverAPI)

	client, err = mongo.Connect(context.TODO(), opts)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

}

func closeMongoDB() {
	if err := client.Disconnect(context.TODO()); err != nil {
		panic(err)
	}
	cancel()
}
