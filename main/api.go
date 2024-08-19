package main

import (
	"database/sql"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

var db *sql.DB
var secretKey = []byte("your secret key")

func main() {
	initDB()
	defer db.Close()

	createTable()
	e := echo.New()
	e.POST("/login", login)
	e.POST("/sign-up", signUp)
	e.GET("/profile", profile)
	e.Logger.Fatal(e.Start(":1323"))
}

// db
func initDB() {
	var err error
	if db, err = sql.Open("mysql", "root@tcp(127.0.0.1:3306)/apiWithJwtToken"); err != nil {
		fmt.Println("can't open database ", err)

		return
	}
	if err := db.Ping(); err != nil {
		fmt.Println("connection failed", err)

		return
	}
}
func createTable() {
	query := `
CREATE TABLE IF NOT EXISTS users(
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email varchar(255) not null,
    password VARCHAR(255) NOT NULL
);`
	tokTable := `
CREATE TABLE IF  NOT EXISTS tokens(
    id int AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    TOKEN VARCHAR(255) NOT NULL UNIQUE
);`
	if _, err := db.Exec(query); err != nil {
		fmt.Println("can't create table", err)

		return
	}
	if _, err := db.Exec(tokTable); err != nil {
		fmt.Println("can't create table", err)

		return
	}
}

// route
func signUp(c echo.Context) error {
	type User struct {
		NAME     string `json:"username"`
		PASSWORD string `json:"password"`
		EMAIL    string `json:"email"`
	}

	u := new(User)

	if err := c.Bind(u); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invalid input"})
	}
	hashpass, err := bcrypt.GenerateFromPassword([]byte(u.PASSWORD), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"message": "hashing error"})
	}

	if _, err := db.Exec(`INSERT INTO users (username,password,email) VALUES (?,?,?)`, u.NAME, hashpass, u.EMAIL); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "insert to table error2"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "User created"})
}
func login(c echo.Context) error {
	type User struct {
		EMAIL    string `json:"email"`
		PASSWORD string `json:"password"`
	}

	u := new(User)

	if err := c.Bind(u); err != nil {

		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invalid input"})
	}
	var storedhashpass string
	var usId int

	if err := db.QueryRow("select password FROM users where email = ?", u.EMAIL).Scan(&storedhashpass); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "invalid username or password1"})
	}
	if err := db.QueryRow(`select id FROM users where email  = ? `, u.EMAIL).Scan(&usId); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "invalid username or password2"})
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedhashpass), []byte(u.PASSWORD)); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "invalid username or password3"})
	}

	token, err := generateToken(usId)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Error generating token"})
	}
	if _, err := db.Exec(`INSERT INTO tokens (userId,TOKEN) VALUES (?,?)`, usId, token); err != nil {

		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "insert to table error"})
	}

	return c.JSON(http.StatusOK, map[string]string{"token": token})

}
func profile2(c echo.Context) error {
	// Extract token from the Authorization header
	tokenString := c.Request().Header.Get("Authorization")
	if tokenString == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "token is missing"})
	}

	// Remove "Bearer " prefix if present
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure that the token's signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "invalid token"})
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "invalid token"})
	}

	// Get user ID from claims
	userID, ok := claims["user_id"].(float64) // Claims are returned as float64
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "user ID not found in token"})
	}

	// Query user information from the database
	var username, email string
	err = db.QueryRow("SELECT username, email FROM users WHERE id = ?", int(userID)).Scan(&username, &email)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "error retrieving user information"})
	}

	// Return the user profile information
	return c.JSON(http.StatusOK, map[string]interface{}{
		"username": username,
		"email":    email,
	})
}
func profile(c echo.Context) error {
	// Extract token from the Authorization header
	tokenString := c.Request().Header.Get("Authorization")
	if tokenString == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "token is missing"})
	}

	// Remove "Bearer " prefix if present
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	// Query to find user ID associated with the token
	var userID int
	err := db.QueryRow("SELECT userId FROM tokens WHERE TOKEN = ?", tokenString).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "invalid or expired token"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "error querying token"})
	}

	// Query to fetch user information from the database
	var username, email string
	err = db.QueryRow("SELECT username, email FROM users WHERE id = ?", userID).Scan(&username, &email)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "error retrieving user information"})
	}

	// Return user profile information
	return c.JSON(http.StatusOK, map[string]interface{}{
		"username": username,
		"email":    email,
	})
}

// utils
func generateToken(id int) (string, error) {

	claims := jwt.MapClaims{
		"user_id": id,
		"exp":     time.Now().Add(time.Hour * 1).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedKey, err := token.SignedString(secretKey)
	if err != nil {

		return "", err
	}

	return signedKey, nil
}
