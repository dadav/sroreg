package main

import (
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	_ "github.com/microsoft/go-mssqldb"
)

type Config struct {
	DBServer     string
	DBPort       int
	DBUser       string
	DBPassword   string
	DBDatabase   string
	ServerPort   string
	TLSEnabled   bool
	TLSCert      string
	TLSKey       string
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	BaseURL      string
}

type SessionData struct {
	UserID    string
	Username  string
	Email     string
	CreatedAt time.Time
}

type ResetTokenData struct {
	Username  string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

var (
	db             *sql.DB
	tmpl           *template.Template
	sessionStore   *sessions.CookieStore
	activeSessions = make(map[string]SessionData)
	sessionMutex   sync.RWMutex
	resetTokens    = make(map[string]ResetTokenData)
	tokenMutex     sync.RWMutex
	config         Config
)

func main() {
	var err error

	// Command-line flags
	dbServer := flag.String("db-server", "", "Database server address")
	dbPort := flag.Int("db-port", 0, "Database server port")
	dbUser := flag.String("db-user", "", "Database user")
	dbPassword := flag.String("db-password", "", "Database password")
	dbDatabase := flag.String("db-database", "", "Database name")
	serverPort := flag.String("port", "", "HTTP server port")
	tlsEnabled := flag.Bool("tls", false, "Enable TLS/HTTPS")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate file")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key file")
	smtpHost := flag.String("smtp-host", "", "SMTP server host")
	smtpPort := flag.Int("smtp-port", 0, "SMTP server port")
	smtpUser := flag.String("smtp-user", "", "SMTP username")
	smtpPassword := flag.String("smtp-password", "", "SMTP password")
	smtpFrom := flag.String("smtp-from", "", "SMTP from address")
	baseURL := flag.String("base-url", "", "Base URL for the application (e.g., https://register.example.com)")
	flag.Parse()

	// Load configuration from environment variables with defaults
	config = Config{
		DBServer:     getEnvOrDefault("DB_SERVER", "localhost"),
		DBPort:       getEnvAsIntOrDefault("DB_PORT", 1433),
		DBUser:       getEnvOrDefault("DB_USER", "sa"),
		DBPassword:   getEnvOrDefault("DB_PASSWORD", ""),
		DBDatabase:   getEnvOrDefault("DB_DATABASE", "SRO_VT_ACCOUNT"),
		ServerPort:   getEnvOrDefault("SERVER_PORT", "8080"),
		TLSEnabled:   getEnvAsBoolOrDefault("TLS_ENABLED", false),
		TLSCert:      getEnvOrDefault("TLS_CERT", ""),
		TLSKey:       getEnvOrDefault("TLS_KEY", ""),
		SMTPHost:     getEnvOrDefault("SMTP_HOST", ""),
		SMTPPort:     getEnvAsIntOrDefault("SMTP_PORT", 587),
		SMTPUser:     getEnvOrDefault("SMTP_USER", ""),
		SMTPPassword: getEnvOrDefault("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnvOrDefault("SMTP_FROM", ""),
		BaseURL:      getEnvOrDefault("BASE_URL", ""),
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
	if *tlsEnabled {
		config.TLSEnabled = *tlsEnabled
	}
	if *tlsCert != "" {
		config.TLSCert = *tlsCert
	}
	if *tlsKey != "" {
		config.TLSKey = *tlsKey
	}
	if *smtpHost != "" {
		config.SMTPHost = *smtpHost
	}
	if *smtpPort != 0 {
		config.SMTPPort = *smtpPort
	}
	if *smtpUser != "" {
		config.SMTPUser = *smtpUser
	}
	if *smtpPassword != "" {
		config.SMTPPassword = *smtpPassword
	}
	if *smtpFrom != "" {
		config.SMTPFrom = *smtpFrom
	}
	if *baseURL != "" {
		config.BaseURL = *baseURL
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

	// Initialize session store with random secret key
	secretKey := make([]byte, 32)
	if _, err := rand.Read(secretKey); err != nil {
		log.Fatal("Error generating session secret: ", err.Error())
	}
	sessionStore = sessions.NewCookieStore(secretKey)
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   config.TLSEnabled,
		SameSite: http.SameSiteLaxMode,
	}

	// Start background cleanup goroutines
	go cleanupExpiredSessions()
	go cleanupExpiredTokens()

	// Parse templates
	tmpl = template.Must(template.ParseFiles(
		"templates/register.html",
		"templates/login.html",
		"templates/profile.html",
		"templates/forgot-password.html",
		"templates/reset-password.html",
	))

	// Setup routes
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/register", handleRegisterPage)
	http.HandleFunc("/profile", requireAuth(handleProfile))
	http.HandleFunc("/logout", requireAuth(handleLogout))
	http.HandleFunc("/change-password", requireAuth(handleChangePassword))
	http.HandleFunc("/forgot-password", handleForgotPassword)
	http.HandleFunc("/reset-password", handleResetPassword)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	serverAddr := ":" + config.ServerPort

	// Start server with or without TLS
	if config.TLSEnabled {
		// Validate TLS configuration
		if config.TLSCert == "" || config.TLSKey == "" {
			log.Fatal("TLS enabled but certificate or key path not provided. Use --tls-cert and --tls-key flags or TLS_CERT and TLS_KEY environment variables")
		}

		log.Printf("Server starting with TLS on https://localhost:%s\n", config.ServerPort)
		log.Fatal(http.ListenAndServeTLS(serverAddr, config.TLSCert, config.TLSKey, nil))
	} else {
		log.Printf("Server starting on http://localhost:%s\n", config.ServerPort)
		log.Fatal(http.ListenAndServe(serverAddr, nil))
	}
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

func getEnvAsBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	sessionData, err := getSession(r)
	if err == nil && sessionData != nil {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		if r.Method == "POST" {
			handleRegister(w, r)
			return
		}
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	// If already logged in, redirect to profile
	sessionData, err := getSession(r)
	if err == nil && sessionData != nil {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	tmpl.ExecuteTemplate(w, "register.html", nil)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	email := strings.TrimSpace(r.FormValue("email"))

	if username == "" || password == "" || email == "" {
		renderError(w, "register.html", "All fields are required")
		return
	}

	if len(username) < 4 || len(username) > 16 {
		renderError(w, "register.html", "Username must be between 4 and 16 characters")
		return
	}

	if !isValidUsername(username) {
		renderError(w, "register.html", "Username can only contain letters and numbers")
		return
	}

	if len(password) < 6 {
		renderError(w, "register.html", "Password must be at least 6 characters")
		return
	}

	if password != confirmPassword {
		renderError(w, "register.html", "Passwords do not match")
		return
	}

	if !isValidEmail(email) {
		renderError(w, "register.html", "Please enter a valid email address")
		return
	}

	var exists int
	err := db.QueryRow("SELECT COUNT(*) FROM dbo.TB_User WHERE StrUserID = @p1", username).Scan(&exists)
	if err != nil {
		log.Println("Database error:", err)
		renderError(w, "register.html", "Database error occurred")
		return
	}

	if exists > 0 {
		renderError(w, "register.html", "Username already exists")
		return
	}

	passwordHash := getMD5Hash(password)

	_, err = db.Exec(`INSERT INTO dbo.TB_User (StrUserID, password, Email, sec_primary, sec_content)
		VALUES (@p1, @p2, @p3, 3, 3)`, username, passwordHash, email)
	if err != nil {
		log.Println("Error inserting user:", err)
		renderError(w, "register.html", "Failed to create account")
		return
	}

	renderSuccess(w, "register.html", "Account created successfully! You can now login.")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to profile
	sessionData, err := getSession(r)
	if err == nil && sessionData != nil {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method != "POST" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if username == "" || password == "" {
		renderError(w, "login.html", "Username and password are required")
		return
	}

	var storedPassword, email string
	err = db.QueryRow("SELECT password, Email FROM dbo.TB_User WHERE StrUserID = @p1", username).Scan(&storedPassword, &email)
	if err != nil {
		if err == sql.ErrNoRows {
			renderError(w, "login.html", "Invalid username or password")
		} else {
			log.Println("Database error:", err)
			renderError(w, "login.html", "Database error occurred")
		}
		return
	}

	passwordHash := getMD5Hash(password)
	if passwordHash != storedPassword {
		renderError(w, "login.html", "Invalid username or password")
		return
	}

	err = createSession(w, r, username, email)
	if err != nil {
		log.Println("Session creation error:", err)
		renderError(w, "login.html", "Failed to create session")
		return
	}

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	sessionData, err := getSession(r)
	if err != nil || sessionData == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Username": sessionData.Username,
		"Email":    sessionData.Email,
	}

	tmpl.ExecuteTemplate(w, "profile.html", data)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	deleteSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	sessionData, err := getSession(r)
	if err != nil || sessionData == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		data := map[string]interface{}{
			"Username": sessionData.Username,
			"Email":    sessionData.Email,
			"Error":    "All fields are required",
		}
		tmpl.ExecuteTemplate(w, "profile.html", data)
		return
	}

	if len(newPassword) < 6 {
		data := map[string]interface{}{
			"Username": sessionData.Username,
			"Email":    sessionData.Email,
			"Error":    "New password must be at least 6 characters",
		}
		tmpl.ExecuteTemplate(w, "profile.html", data)
		return
	}

	if newPassword != confirmPassword {
		data := map[string]interface{}{
			"Username": sessionData.Username,
			"Email":    sessionData.Email,
			"Error":    "New passwords do not match",
		}
		tmpl.ExecuteTemplate(w, "profile.html", data)
		return
	}

	var storedPassword string
	err = db.QueryRow("SELECT password FROM dbo.TB_User WHERE StrUserID = @p1", sessionData.Username).Scan(&storedPassword)
	if err != nil {
		log.Println("Database error:", err)
		data := map[string]interface{}{
			"Username": sessionData.Username,
			"Email":    sessionData.Email,
			"Error":    "Database error occurred",
		}
		tmpl.ExecuteTemplate(w, "profile.html", data)
		return
	}

	currentPasswordHash := getMD5Hash(currentPassword)
	if currentPasswordHash != storedPassword {
		data := map[string]interface{}{
			"Username": sessionData.Username,
			"Email":    sessionData.Email,
			"Error":    "Current password is incorrect",
		}
		tmpl.ExecuteTemplate(w, "profile.html", data)
		return
	}

	newPasswordHash := getMD5Hash(newPassword)
	_, err = db.Exec("UPDATE dbo.TB_User SET password = @p1 WHERE StrUserID = @p2", newPasswordHash, sessionData.Username)
	if err != nil {
		log.Println("Error updating password:", err)
		data := map[string]interface{}{
			"Username": sessionData.Username,
			"Email":    sessionData.Email,
			"Error":    "Failed to update password",
		}
		tmpl.ExecuteTemplate(w, "profile.html", data)
		return
	}

	data := map[string]interface{}{
		"Username": sessionData.Username,
		"Email":    sessionData.Email,
		"Success":  "Password changed successfully!",
	}
	tmpl.ExecuteTemplate(w, "profile.html", data)
}

func handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "forgot-password.html", nil)
		return
	}

	if r.Method != "POST" {
		http.Redirect(w, r, "/forgot-password", http.StatusSeeOther)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))

	if email == "" || !isValidEmail(email) {
		renderError(w, "forgot-password.html", "Please enter a valid email address")
		return
	}

	var username string
	err := db.QueryRow("SELECT StrUserID FROM dbo.TB_User WHERE Email = @p1", email).Scan(&username)

	if err == nil {
		token := uuid.New().String()
		tokenData := ResetTokenData{
			Username:  username,
			Email:     email,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		tokenMutex.Lock()
		resetTokens[token] = tokenData
		tokenMutex.Unlock()

		// Get base URL from config or detect from request
		baseURL := getBaseURL(r)

		err = sendPasswordResetEmail(email, token, baseURL)
		if err != nil {
			log.Println("Error sending email:", err)
		}
	}

	renderSuccess(w, "forgot-password.html", "If an account exists with that email, a password reset link has been sent.")
}

func handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		token := r.URL.Query().Get("token")
		if token == "" {
			renderError(w, "reset-password.html", "Invalid reset link")
			return
		}

		tokenMutex.RLock()
		tokenData, exists := resetTokens[token]
		tokenMutex.RUnlock()

		if !exists || time.Now().After(tokenData.ExpiresAt) {
			renderError(w, "reset-password.html", "Reset link has expired or is invalid")
			return
		}

		data := map[string]interface{}{
			"Token": token,
		}
		tmpl.ExecuteTemplate(w, "reset-password.html", data)
		return
	}

	if r.Method != "POST" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	token := r.FormValue("token")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if token == "" || newPassword == "" || confirmPassword == "" {
		data := map[string]interface{}{
			"Token": token,
			"Error": "All fields are required",
		}
		tmpl.ExecuteTemplate(w, "reset-password.html", data)
		return
	}

	if len(newPassword) < 6 {
		data := map[string]interface{}{
			"Token": token,
			"Error": "Password must be at least 6 characters",
		}
		tmpl.ExecuteTemplate(w, "reset-password.html", data)
		return
	}

	if newPassword != confirmPassword {
		data := map[string]interface{}{
			"Token": token,
			"Error": "Passwords do not match",
		}
		tmpl.ExecuteTemplate(w, "reset-password.html", data)
		return
	}

	tokenMutex.Lock()
	tokenData, exists := resetTokens[token]
	if exists {
		delete(resetTokens, token)
	}
	tokenMutex.Unlock()

	if !exists || time.Now().After(tokenData.ExpiresAt) {
		data := map[string]interface{}{
			"Token": token,
			"Error": "Reset link has expired or is invalid",
		}
		tmpl.ExecuteTemplate(w, "reset-password.html", data)
		return
	}

	newPasswordHash := getMD5Hash(newPassword)
	_, err := db.Exec("UPDATE dbo.TB_User SET password = @p1 WHERE StrUserID = @p2", newPasswordHash, tokenData.Username)
	if err != nil {
		log.Println("Error updating password:", err)
		data := map[string]interface{}{
			"Token": token,
			"Error": "Failed to reset password",
		}
		tmpl.ExecuteTemplate(w, "reset-password.html", data)
		return
	}

	data := map[string]interface{}{
		"Success": "Password reset successfully! You can now login with your new password.",
	}
	tmpl.ExecuteTemplate(w, "login.html", data)
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

func renderError(w http.ResponseWriter, templateName string, message string) {
	data := map[string]interface{}{
		"Error": message,
	}
	tmpl.ExecuteTemplate(w, templateName, data)
}

func renderSuccess(w http.ResponseWriter, templateName string, message string) {
	data := map[string]interface{}{
		"Success": message,
	}
	tmpl.ExecuteTemplate(w, templateName, data)
}

func renderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	tmpl.ExecuteTemplate(w, templateName, data)
}

// Session helper functions
func getSession(r *http.Request) (*SessionData, error) {
	// Get session - ignore cookie validation errors
	session, _ := sessionStore.Get(r, "silkroad_session")
	if session == nil {
		return nil, fmt.Errorf("no session")
	}

	sessionID, ok := session.Values["session_id"].(string)
	if !ok || sessionID == "" {
		return nil, fmt.Errorf("no valid session")
	}

	sessionMutex.RLock()
	sessionData, exists := activeSessions[sessionID]
	sessionMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired (24 hours)
	if time.Since(sessionData.CreatedAt) > 24*time.Hour {
		sessionMutex.Lock()
		delete(activeSessions, sessionID)
		sessionMutex.Unlock()
		return nil, fmt.Errorf("session expired")
	}

	return &sessionData, nil
}

func createSession(w http.ResponseWriter, r *http.Request, username, email string) error {
	// Get session - ignore errors as this might be a new session
	session, _ := sessionStore.Get(r, "silkroad_session")

	// Clear any existing values
	session.Values = make(map[interface{}]interface{})

	sessionID := uuid.New().String()
	sessionData := SessionData{
		UserID:    sessionID,
		Username:  username,
		Email:     email,
		CreatedAt: time.Now(),
	}

	sessionMutex.Lock()
	activeSessions[sessionID] = sessionData
	sessionMutex.Unlock()

	session.Values["session_id"] = sessionID
	return session.Save(r, w)
}

func deleteSession(w http.ResponseWriter, r *http.Request) {
	// Get session - ignore errors
	session, _ := sessionStore.Get(r, "silkroad_session")
	if session == nil {
		return
	}

	sessionID, ok := session.Values["session_id"].(string)
	if ok && sessionID != "" {
		sessionMutex.Lock()
		delete(activeSessions, sessionID)
		sessionMutex.Unlock()
	}

	session.Options.MaxAge = -1
	session.Save(r, w)
}

func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionData, err := getSession(r)
		if err != nil || sessionData == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		handler(w, r)
	}
}

func cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		sessionMutex.Lock()
		for id, session := range activeSessions {
			if time.Since(session.CreatedAt) > 24*time.Hour {
				delete(activeSessions, id)
			}
		}
		sessionMutex.Unlock()
	}
}

func cleanupExpiredTokens() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		tokenMutex.Lock()
		for token, data := range resetTokens {
			if time.Now().After(data.ExpiresAt) {
				delete(resetTokens, token)
			}
		}
		tokenMutex.Unlock()
	}
}

func getBaseURL(r *http.Request) string {
	// If BASE_URL is configured, use it
	if config.BaseURL != "" {
		return config.BaseURL
	}

	// Try to detect from reverse proxy headers (Caddy, Nginx, etc.)
	scheme := "http"
	host := r.Host

	// Check X-Forwarded-Proto header (set by reverse proxies)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if proto := r.Header.Get("X-Forwarded-Ssl"); proto == "on" {
		scheme = "https"
	} else if r.TLS != nil || config.TLSEnabled {
		scheme = "https"
	}

	// Check X-Forwarded-Host header (set by reverse proxies)
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func sendPasswordResetEmail(email, resetToken, domain string) error {
	if config.SMTPHost == "" || config.SMTPUser == "" || config.SMTPPassword == "" {
		return fmt.Errorf("SMTP not configured")
	}

	resetLink := fmt.Sprintf("%s/reset-password?token=%s", domain, resetToken)

	subject := "Silkroad Online - Password Reset Request"
	body := fmt.Sprintf(`Hello,

You have requested to reset your password for your Silkroad Online account.

Please click the link below to reset your password:
%s

This link will expire in 1 hour.

If you did not request this password reset, please ignore this email.

Best regards,
Silkroad Online Team`, resetLink)

	auth := smtp.PlainAuth("", config.SMTPUser, config.SMTPPassword, config.SMTPHost)

	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)

	message := fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n"+
			"\r\n%s",
		config.SMTPFrom,
		email,
		subject,
		body,
	)

	return smtp.SendMail(addr, auth, config.SMTPFrom, []string{email}, []byte(message))
}
