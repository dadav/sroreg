package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	_ "github.com/microsoft/go-mssqldb"
)

type Config struct {
	DBServer   string
	DBPort     int
	DBUser     string
	DBPassword string
	DBDatabase string
	ServerPort string
}

var db *sql.DB
var tmpl *template.Template

func main() {
	var err error

	// Command-line flags
	dbServer := flag.String("db-server", "", "Database server address")
	dbPort := flag.Int("db-port", 0, "Database server port")
	dbUser := flag.String("db-user", "", "Database user")
	dbPassword := flag.String("db-password", "", "Database password")
	dbDatabase := flag.String("db-database", "", "Database name")
	serverPort := flag.String("port", "", "HTTP server port")
	flag.Parse()

	// Load configuration from environment variables with defaults
	config := Config{
		DBServer:   getEnvOrDefault("DB_SERVER", "localhost"),
		DBPort:     getEnvAsIntOrDefault("DB_PORT", 1433),
		DBUser:     getEnvOrDefault("DB_USER", "sa"),
		DBPassword: getEnvOrDefault("DB_PASSWORD", ""),
		DBDatabase: getEnvOrDefault("DB_DATABASE", "SRO_VT_ACCOUNT"),
		ServerPort: getEnvOrDefault("SERVER_PORT", "8080"),
	}

	// Override with command-line flags if provided
	if *dbServer != "" {
		config.DBServer = *dbServer
	}
	if *dbPort != 0 {
		config.DBPort = *dbPort
	}
	if *dbUser != "" {
		config.DBUser = *dbUser
	}
	if *dbPassword != "" {
		config.DBPassword = *dbPassword
	}
	if *dbDatabase != "" {
		config.DBDatabase = *dbDatabase
	}
	if *serverPort != "" {
		config.ServerPort = *serverPort
	}

	// Check if password is set
	if config.DBPassword == "" {
		log.Fatal("Database password must be set via DB_PASSWORD environment variable or --db-password flag")
	}

	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;database=%s",
		config.DBServer, config.DBUser, config.DBPassword, config.DBPort, config.DBDatabase)

	db, err = sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal("Error creating connection pool: ", err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Error connecting to database: ", err.Error())
	}

	log.Printf("Connected to database %s@%s:%d/%s successfully!\n",
		config.DBUser, config.DBServer, config.DBPort, config.DBDatabase)

	tmpl = template.Must(template.ParseFiles("templates/register.html"))

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/register", handleRegister)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	serverAddr := ":" + config.ServerPort
	log.Printf("Server starting on http://localhost:%s\n", config.ServerPort)
	log.Fatal(http.ListenAndServe(serverAddr, nil))
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
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
