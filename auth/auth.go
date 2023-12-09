package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"time"
)

var db *sql.DB

func Register(w http.ResponseWriter, r *http.Request) {
	log.Println("Registering")

	// Parse the request body to get account credentials
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate the email
	if _, err := mail.ParseAddress(creds.Email); err != nil {
		http.Error(w, "Invalid email address: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verify if the account already exists
	var storedEmail string
	err = db.QueryRow(`SELECT username FROM account WHERE username = $1`, creds.Email).Scan(&storedEmail)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Error while querying the database: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Account already exists", http.StatusBadRequest)
		return
	}

	if len(creds.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters long", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error while hashing the password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Insert the account into the database
	_, err = db.Exec(`INSERT INTO account(username, password) VALUES($1, $2)`, creds.Email, hashedPassword)
	if err != nil {
		http.Error(w, "Error while storing account: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

var jwtKey = []byte(os.Getenv("JWT_KEY"))

func SignIn(w http.ResponseWriter, r *http.Request) {
	log.Println("Signing in")

	// Parse the request body
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the account's hashed password from the database
	var storedHashedPassword string
	err = db.QueryRow(`SELECT password FROM account WHERE username = $1`, creds.Email).Scan(&storedHashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "account not found", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error while querying the database: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Invalid credentials: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Create a new token object, specifying signing method and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": creds.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	// Sign the token with our secret key
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error while signing the token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte(tokenString))
}

func ValidateToken(w http.ResponseWriter, r *http.Request) {
	log.Println("Validating token")

	type TokenRequest struct {
		Token string `json:"token"`
	}

	var req TokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenString := req.Token

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"], err.Error())
		}
		return jwtKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Token is valid
		email := claims["email"].(string)
		exp := claims["exp"].(float64)

		response := struct {
			Email string  `json:"email"`
			Exp   float64 `json:"exp"`
		}{
			Email: email,
			Exp:   exp,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
	}
}

func DeleteAccount(w http.ResponseWriter, r *http.Request) {
	log.Println("Deleting account")

	// Parse the request body
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the account's hashed password from the database
	var storedHashedPassword string
	err = db.QueryRow(`SELECT password FROM account WHERE username = $1`, creds.Email).Scan(&storedHashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "account not found", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error while querying the database: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Invalid credentials: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Delete the account from the database
	_, err = db.Exec(`DELETE FROM account WHERE username = $1`, creds.Email)
	if err != nil {
		http.Error(w, "Error while deleting account: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	secretName := "SecretsRDS"
	region := "sa-east-1"

	// Load the Shared AWS Configuration (~/.aws/config)
	config, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// Create an Amazon Secrets Manager client
	client := secretsmanager.NewFromConfig(config)

	// Build the request with its input parameters
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	// Retrieve the secret value
	result, err := client.GetSecretValue(context.Background(), input)
	if err != nil {
		log.Fatalf("got an error retrieving the secret value: %s", err)
	}

	// SecretString is a JSON string, so we need to unmarshal it into a map that can accept any type of JSON values
	var secretMap map[string]interface{}
	err = json.Unmarshal([]byte(*result.SecretString), &secretMap)
	if err != nil {
		log.Fatalf("json.Unmarshal error: %s", err)
	}

	// Access individual values by casting them to the expected type
	dbUser := getString(secretMap, "username")
	dbPassword := getString(secretMap, "password")
	dbEngine := getString(secretMap, "engine")
	dbHost := getString(secretMap, "host")

	// Construct the connection string
	connectionString := fmt.Sprintf("%s://%s:%s@%s:5432/auth?sslmode=require",
		dbEngine, dbUser, dbPassword, dbHost)

	// Open a connection to the PostgreSQL database
	db, err = sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}

	// Check if the connection to the database is successful
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	// Create a new Gorilla Mux router
	r := mux.NewRouter()

	r.HandleFunc("/auth/register", Register).Methods("POST")
	r.HandleFunc("/auth/signin", SignIn).Methods("POST")
	r.HandleFunc("/auth/validate", ValidateToken).Methods("POST")
	r.HandleFunc("/auth/delete", DeleteAccount).Methods("DELETE")
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")

	// Start the HTTP server
	http.ListenAndServe(":8080", r)
}

// getString helps in retrieving string values from the map and handles type assertion
func getString(m map[string]interface{}, key string) string {
	value, ok := m[key].(string)
	if !ok {
		log.Fatalf("The secret does not contain '%s' or it is not a string.", key)
	}
	return value
}
