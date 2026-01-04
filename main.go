package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strings"

	_ "github.com/microsoft/go-mssqldb"
)

type Config struct {
	Server   string
	Port     int
	User     string
	Password string
	Database string
}

var db *sql.DB
var tmpl *template.Template

func main() {
	var err error

	config := Config{
		Server:   "localhost",
		Port:     1433,
		User:     "sa",
		Password: "Foobarfoobar2",
		Database: "SRO_VT_ACCOUNT",
	}

	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;database=%s",
		config.Server, config.User, config.Password, config.Port, config.Database)

	db, err = sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal("Error creating connection pool: ", err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Error connecting to database: ", err.Error())
	}

	log.Println("Connected to database successfully!")

	tmpl = template.Must(template.ParseFiles("templates/register.html"))

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/register", handleRegister)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl.Execute(w, nil)
	}
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	email := strings.TrimSpace(r.FormValue("email"))

	if username == "" || password == "" || email == "" {
		renderError(w, "All fields are required")
		return
	}

	if len(username) < 4 || len(username) > 16 {
		renderError(w, "Username must be between 4 and 16 characters")
		return
	}

	if !isValidUsername(username) {
		renderError(w, "Username can only contain letters and numbers")
		return
	}

	if len(password) < 6 {
		renderError(w, "Password must be at least 6 characters")
		return
	}

	if password != confirmPassword {
		renderError(w, "Passwords do not match")
		return
	}

	if !isValidEmail(email) {
		renderError(w, "Please enter a valid email address")
		return
	}

	var exists int
	err := db.QueryRow("SELECT COUNT(*) FROM dbo.TB_User WHERE StrUserID = @p1", username).Scan(&exists)
	if err != nil {
		log.Println("Database error:", err)
		renderError(w, "Database error occurred")
		return
	}

	if exists > 0 {
		renderError(w, "Username already exists")
		return
	}

	passwordHash := getMD5Hash(password)

	_, err = db.Exec(`INSERT INTO dbo.TB_User (StrUserID, password, Email, sec_primary, sec_content)
		VALUES (@p1, @p2, @p3, 3, 3)`, username, passwordHash, email)
	if err != nil {
		log.Println("Error inserting user:", err)
		renderError(w, "Failed to create account")
		return
	}

	renderSuccess(w, "Account created successfully!")
}

func isValidUsername(username string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9]+$", username)
	return match
}

func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func getMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func renderError(w http.ResponseWriter, message string) {
	data := map[string]interface{}{
		"Error": message,
	}
	tmpl.Execute(w, data)
}

func renderSuccess(w http.ResponseWriter, message string) {
	data := map[string]interface{}{
		"Success": message,
	}
	tmpl.Execute(w, data)
}
