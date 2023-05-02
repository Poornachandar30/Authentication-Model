package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"database/sql"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var resultRes ValidationRes

type RegisterUser struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResDTO struct {
	AuthToken string `json:"authToken"`
}

type ValidationRes struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type User struct {
	ID    int
	Name  string
	Email string
	Hash  string
}

type UserInfoStruct struct {
	ID               int
	Name             string
	Email            string
	LastModifiedBy   string
	LastModifiedDate string
}

func main() {
	var err error
	db, err = sql.Open("mysql", "root:Admin@123@tcp(localhost:3306)/guvigeeks")
	if err != nil {
		fmt.Println("Openning DB Error:")
		panic(err.Error())
	}
	fmt.Print(*db)
	defer db.Close()

	// Checking the connection to the database is working
	err = db.Ping()
	if err != nil {
		fmt.Println("Error connecting to DB:", err.Error())
		return
	}

	fmt.Println("Successfully connected to the database!")
	//Register API Route
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			// Set the CORS headers
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusOK)
		}
		if r.Method == "POST" {
			var registerUser RegisterUser
			err := json.NewDecoder(r.Body).Decode(&registerUser)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}

			fmt.Printf("Received user: %+v\n", registerUser)

			hashedValue, hashingError := HashPassword(registerUser.Password)

			if hashingError != nil {
				resultRes.Code = 500
				resultRes.Message = hashingError.Error()
				writeResponse(w, resultRes.Code, resultRes)
			}

			fmt.Println("hashed value : ", hashedValue)

			res, createNewUsererr := createNewUser(registerUser, hashedValue)

			if createNewUsererr != nil {
				writeResponse(w, resultRes.Code, resultRes)
			}

			if res > 0 {
				resultRes.Code = 200
				resultRes.Message = "User Created SUccesslly"
				writeResponse(w, http.StatusOK, resultRes)
			}

		} else {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		}
	})

	//Login API Route
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			// Set the CORS headers
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusOK)
		}
		if r.Method == "POST" {
			var loginUser LoginUser
			err := json.NewDecoder(r.Body).Decode(&loginUser)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}

			fmt.Printf("Received user: %+v\n", loginUser)

			loginRes, loginErr := getLoginInfo(loginUser)

			fmt.Println("loginRes", loginRes)

			if loginErr != nil {
				writeResponse(w, resultRes.Code, resultRes)
			}

			if len(loginRes) == 0 {
				resultRes.Code = 400
				resultRes.Message = "Invalid Username"
				writeResponse(w, resultRes.Code, resultRes)
			}

			// fmt.Println("hashed value : ", hashedValue)

			if len(loginRes) > 0 {

				verifyPassword := CheckPasswordHash(loginUser.Password, loginRes[0].Hash)

				fmt.Println("Compared password :", verifyPassword)

				if !verifyPassword {
					resultRes.Code = 400
					resultRes.Message = "Incorrect Password"
					writeResponse(w, resultRes.Code, resultRes)

				} else {
					authToken, authError := generateJWTtoken(strconv.Itoa(loginRes[0].ID))

					if authError != nil {
						writeResponse(w, resultRes.Code, resultRes)
					}
					var loginResponse LoginResDTO

					if authToken != "" {
						loginResponse.AuthToken = authToken
					}

					writeResponse(w, http.StatusOK, loginResponse)

				}

			}

		} else {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/profile", handler)

	http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		// Set the CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
	}
	authHeader := r.Header.Get("Authorization")
	fmt.Println("Authe header", authHeader)
	token := strings.Split(authHeader, " ")[1]
	claims := jwt.MapClaims{}
	tokenString, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("guviGeeks"), nil
	})

	if claims, ok := tokenString.Claims.(jwt.MapClaims); ok && tokenString.Valid {
		// Access the userId value
		userId, _ := strconv.Atoi(claims["userId"].(string))
		fmt.Println("userId:", userId)

		userDetails, userDetailsError := getUserInfo(userId)

		if userDetailsError != nil {
			writeResponse(w, resultRes.Code, resultRes)
		}

		if len(userDetails) > 0 {
			writeResponse(w, http.StatusOK, userDetails)

		} else {
			//No content 204
			NoContent(w)
		}

	} else {
		//err handle
		resultRes.Code = 500
		resultRes.Message = err.Error()
		writeResponse(w, resultRes.Code, resultRes)
	}

}

func getUserInfo(userId int) ([]UserInfoStruct, error) {

	// Execute the SELECT query
	query := "SELECT userId, username, email, last_modified_by ,last_modified_date  FROM sys.users WHERE userId = ?"
	rows, err := db.Query(query, userId)
	if err != nil {
		resultRes.Code = 500
		resultRes.Message = err.Error()
		return nil, err
	}
	defer rows.Close()

	// Iterate through the rows and store the results in a struct

	var userInfo []UserInfoStruct
	for rows.Next() {
		var user UserInfoStruct
		err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.LastModifiedBy, &user.LastModifiedDate)
		if err != nil {
			fmt.Println("Iterate through the rows and store", err.Error())
			resultRes.Code = 500
			resultRes.Message = err.Error()
			return nil, err
		}
		userInfo = append(userInfo, user)
	}

	fmt.Println("Select Response", userInfo)
	return userInfo, nil
}

func getLoginInfo(loginJson LoginUser) ([]User, error) {

	// Execute the SELECT query
	query := "SELECT userId, username, email, password FROM sys.users WHERE email = ?"
	rows, err := db.Query(query, loginJson.Email)
	if err != nil {
		resultRes.Code = 500
		resultRes.Message = err.Error()
		return nil, err
	}
	defer rows.Close()

	// Iterate through the rows and store the results in a struct

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Hash)
		if err != nil {
			fmt.Println("Iterate through the rows and store", err.Error())
			resultRes.Code = 500
			resultRes.Message = err.Error()
			return nil, err
		}
		users = append(users, user)
	}

	fmt.Println("Select Response", users)

	return users, nil
}

func createNewUser(userJson RegisterUser, hash string) (int64, error) {

	// Prepare the INSERT statement
	stmt, err := db.Prepare("INSERT INTO sys.users (username, email, password, last_modified_by, created_by) VALUES (?, ?, ?, ?, ?)")

	if err != nil {
		resultRes.Code = 500
		resultRes.Message = err.Error()
		return 0, err
	}
	defer stmt.Close()

	// Executing the INSERT statement with the request parameters
	result, err := stmt.Exec(userJson.Name, userJson.Email, hash, "admin", "admin")

	if err != nil {

		if strings.Contains(err.Error(), "for key 'users.email") && strings.Contains(err.Error(), "Duplicate entry") {
			resultRes.Code = 400
			resultRes.Message = "Email ID already exist in DB"
			return 0, err
		}

		resultRes.Code = 500
		resultRes.Message = err.Error()
		return 0, err
	}

	// Printing the number of rows affected by the INSERT statement
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		resultRes.Code = 500
		resultRes.Message = "Email ID already exist in DB"
		return 0, err
	}
	log.Printf("Inserted %d rows", rowsAffected)

	return rowsAffected, nil
}

func generateJWTtoken(userId string) (string, error) {
	// Set the signing method and secret key
	signingMethod := jwt.SigningMethodHS256
	secretKey := []byte("guviGeeks")

	// Set the expiration time for the token
	expirationTime := time.Now().Add(24 * time.Hour)

	// Define the payload as a map containing only the userId field
	payload := jwt.MapClaims{
		"userId": userId,
		"exp":    expirationTime.Unix(),
	}

	// Generate the token with the payload and sign it with the secret key
	token := jwt.NewWithClaims(signingMethod, payload)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		resultRes.Code = 500
		resultRes.Message = err.Error()
		return "", err
	}

	// Print the generated token
	fmt.Println(signedToken)

	return signedToken, nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Print("Failed while writing response", err.Error())
		panic(err)
	}
}

func NoContent(w http.ResponseWriter) {
	// send the headers with a 204 response code.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	w.WriteHeader(http.StatusNoContent)
}
