# Overview
This project provides basic authentication functionalities using the Gin framework in Golang. It includes user registration, login, and user retrieval endpoints. Authentication is handled via JWT tokens.

## Prerequisites
Golang installed
PostgreSQL database
Environment variables configured for database and JWT

## Setup
### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd <repository-directory>
```

### Step 2: Set Up Environment Variables
Create a .env file in the root directory of the project and add the following variables:

```dotenv
POSTGRES_HOST=your_postgres_host
POSTGRES_USER=your_postgres_user
POSTGRES_PASSWORD=your_postgres_password
POSTGRES_DATABASE=your_postgres_db
POSTGRES_PORT=your_postgres_port
JWT_SECRET_KEY=your_jwt_secret_key
```

### Step 3: Install Dependencies
```bash
go mod tidy
```

### Step 4: Run Database Migrations
Make sure your PostgreSQL database is running and execute the following command to auto-migrate the models:

```go
package main

import (
"golang/src/models"
)

func main() {
models.OpenDatabaseConnection()
models.AutoMigrateModels()
}
```

Run the above script using:

```bash
go run main.go
```

### Step 5: Start the Server
```bash
go run main.go
```

The server will start at http://localhost:8080.

## API Endpoints

### Register
Endpoint: POST /api/auth/register

Description: Register a new user.

Request Body:

```json
{
"email": "user@example.com",
"password": "password123"
}
```

Response:

```json
{
"status": "success",
"message": "Startup saved successfully",
"data": {
"user": {
"ID": 1,
"Email": "user@example.com"
},
"token": "jwt_token_here"
}
}
```

### Login
Endpoint: POST /api/auth/login

Description: Log in an existing user.

Request Body:

```json
{
"email": "user@example.com",
"password": "password123"
}
```

Response:

```json
{
"status": "success",
"message": "Startup saved successfully",
"data": {
"user": {
"ID": 1,
"Email": "user@example.com"
},
"token": "jwt_token_here"
}
}
```

### Get Users
Endpoint: GET /api/users

Description: Retrieve all users. This endpoint is protected and requires a valid JWT token in the Authorization header.

Request Header:

```http
Authorization: Bearer <jwt_token_here>
```

Response:

```json
{
"status": "success",
"message": "Users retrieved successfully",
"data": [
{
"ID": 1,
"Email": "user@example.com"
},
{
"ID": 2,
"Email": "anotheruser@example.com"
}
]
}
```

## Middleware
### Authentication Middleware
The AuthMiddleware function checks for the presence of a valid JWT token in the Authorization header of incoming requests. If the token is missing or invalid, it returns a 401 Unauthorized response.

```go
package middlewares

import (
"golang/src/models"
"log"
"strings"

arduino
Copy code
"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
return func(c *gin.Context) {
var token = c.GetHeader("Authorization")
if token == "" {
c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized to perform request. Please get a valid API key"})
return
}

go
Copy code
	// Extract Bearer token
	const bearerPrefix = "Bearer "
	splitToken := strings.Split(token, bearerPrefix)
	var reqToken = splitToken[1]

	if reqToken == "" {
		c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token format. Bearer token required"})
		return
	}

	claims, err := models.DecodeToken(reqToken)
	if err != nil {
		log.Printf("Error decoding token: %v\n", err)
		return
	}

	log.Printf("Claims: %v\n", claims)

	c.Set("userId", 1)

	c.Next()
}
}
```

## Models
### User Model
The User model includes fields for email and password, as well as methods for registering and logging in users. Passwords are hashed using bcrypt.

```go
package models

import (
"errors"

arduino
Copy code
"golang.org/x/crypto/bcrypt"
"gorm.io/gorm"
)

type User struct {
gorm.Model
Email string json:"email" gorm:"unique"
Password string json:"password"
}

func (user *User) HashPassword() error {
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
user.Password = string(hashedPassword)
return err
}

func CheckPasswordHash(password, hash string) bool {
err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
return err == nil
}

func (user *User) Register() (*AuthResponse, error) {
var err error
userFromDb := FetchUserByEmail(user.Email)

go
Copy code
if userFromDb.Email != "" {
	err = errors.New("email already taken")
	return &AuthResponse{}, err
}

err = user.HashPassword()
if err != nil {
	return &AuthResponse{}, err
}

err = Database.Model(&user).Create(user).Error
if err != nil {
	return &AuthResponse{}, err
}

token, err := GenerateJWT(user.ID)
if err != nil {
	return &AuthResponse{}, err
}

response := AuthResponse{
	User:  user,
	Token: token,
}

return &response, nil
}

func (user *User) Login() (*AuthResponse, error) {
var err error
userFromDb := FetchUserByEmail(user.Email)

go
Copy code
if userFromDb.Email == "" {
	err = errors.New("User or password incorrect")
	return &AuthResponse{}, err
}

var isCheckedPassword = CheckPasswordHash(user.Password, userFromDb.Password)
if !isCheckedPassword {
	err = errors.New("User or password incorrect")
	return &AuthResponse{}, err
}

token, err := GenerateJWT(user.ID)
if err != nil {
	return &AuthResponse{}, err
}

response := AuthResponse{
	User:  &userFromDb,
	Token: token,
}

return &response, nil
}
```

## Routes
The routes for authentication and user retrieval are defined in the routes package.

```go
package routes

import (
"golang/src/controllers"
"golang/src/middlewares"

arduino
Copy code
"github.com/gin-gonic/gin"
)

func startupsGroupRouter(baseRouter *gin.RouterGroup) {
startups := baseRouter.Group("/auth")

arduino
Copy code
startups.POST("/login", controllers.Login)
startups.POST("/register", controllers.Register)
}

func SetupRoutes() *gin.Engine {
r := gin.Default()

css
Copy code
versionRouter := r.Group("/api")

startupsGroupRouter(versionRouter)
versionRouter.GET("/users",
	middlewares.AuthMiddleware(), controllers.GetUsers)
return r
}
```

## Conclusion
This project provides a basic authentication system using Gin and JWT tokens. It includes user registration, login, and protected user retrieval endpoints. Follow the setup instructions to get the server running and test the API endpoints.
