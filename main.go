package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Produk struct {
	ID    int    `json:"id"`
	Nama  string `json:"nama"`
	Harga int    `json:"harga"`
	Stok  int    `json:"stok"`
}

type Category struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Transaksi struct {
	ID       int    `json:"id"`
	ProdukID int    `json:"produk_id"`
	Jumlah   int    `json:"jumlah"`
	Total    int    `json:"total"`
	Tanggal  string `json:"tanggal"`
}

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

var db *sql.DB
var jwtKey = []byte("rahasia-super-kasir")

func main() {

	var err error

	db, err = sql.Open("sqlite", "./kasir.db")
	if err != nil {
		panic(err)
	}

	createTable()

	// Routing
	http.HandleFunc("/produk", enableCORS(authMiddleware(produkHandler)))
	http.HandleFunc("/produk/", enableCORS(authMiddleware(produkByIDHandler)))

	http.HandleFunc("/transaksi", enableCORS(authMiddleware(transaksiHandler)))
	http.HandleFunc("/laporan", enableCORS(authMiddleware(laporanHandler)))

	http.HandleFunc("/register", enableCORS(registerHandler))
	http.HandleFunc("/login", enableCORS(loginHandler))

	http.HandleFunc("/categories", enableCORS(authMiddleware(categoriesHandler)))
	http.HandleFunc("/categories/", enableCORS(authMiddleware(categoryByIDHandler)))

	fmt.Println("SERVER BARU JWT AKTIF 🔐🔥 http://localhost:8080")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.ListenAndServe(":"+port, nil)

}

// ================= DATABASE ============git add .

func createTable() {

	produkTable := `
	CREATE TABLE IF NOT EXISTS produk (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		nama TEXT,
		harga INTEGER,
		stok INTEGER
	);
	`

	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password TEXT
	);
	`

	transaksiTable := `
	CREATE TABLE IF NOT EXISTS transaksi (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		produk_id INTEGER,
		jumlah INTEGER,
		total INTEGER,
		tanggal TEXT
	);
	`
	categoryTable := `
	CREATE TABLE IF NOT EXISTS categories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		description TEXT
	);
	`

	db.Exec(produkTable)
	db.Exec(userTable)
	db.Exec(transaksiTable)
	db.Exec(categoryTable)

}

// ================= PRODUK =================

func produkHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {

		rows, err := db.Query("SELECT id,nama,harga,stok FROM produk")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()

		var list []Produk

		for rows.Next() {
			var p Produk
			rows.Scan(&p.ID, &p.Nama, &p.Harga, &p.Stok)
			list = append(list, p)
		}

		json.NewEncoder(w).Encode(list)
		return
	}

	if r.Method == "POST" {

		var p Produk
		json.NewDecoder(r.Body).Decode(&p)

		db.Exec(
			"INSERT INTO produk(nama,harga,stok) VALUES(?,?,?)",
			p.Nama, p.Harga, p.Stok,
		)

		json.NewEncoder(w).Encode(Response{
			Status:  "success",
			Message: "Produk ditambah",
		})
		return
	}

	http.Error(w, "Method not allowed", 405)
}

func produkByIDHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	idStr := strings.TrimPrefix(r.URL.Path, "/produk/")
	id, _ := strconv.Atoi(idStr)

	if r.Method == "DELETE" {

		db.Exec("DELETE FROM produk WHERE id=?", id)

		json.NewEncoder(w).Encode(Response{
			Status:  "success",
			Message: "Produk dihapus",
		})
		return
	}

	http.Error(w, "Method not allowed", 405)
}

// ================= AUTH =================

func registerHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var u User
	json.NewDecoder(r.Body).Decode(&u)

	hash, _ := bcrypt.GenerateFromPassword(
		[]byte(u.Password),
		bcrypt.DefaultCost,
	)

	_, err := db.Exec(
		"INSERT INTO users(username,password) VALUES(?,?)",
		u.Username,
		string(hash),
	)

	if err != nil {
		http.Error(w, "Username sudah ada", 400)
		return
	}

	json.NewEncoder(w).Encode(Response{
		Status:  "success",
		Message: "Register berhasil",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var u User
	var dbUser User

	json.NewDecoder(r.Body).Decode(&u)

	err := db.QueryRow(
		"SELECT id,password FROM users WHERE username=?",
		u.Username,
	).Scan(&dbUser.ID, &dbUser.Password)

	if err != nil {
		http.Error(w, "User tidak ada", 401)
		return
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(dbUser.Password),
		[]byte(u.Password),
	)

	if err != nil {
		http.Error(w, "Password salah", 401)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": dbUser.ID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, _ := token.SignedString(jwtKey)

	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

func categoriesHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	// GET ALL
	if r.Method == "GET" {

		rows, err := db.Query("SELECT id,name,description FROM categories")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()

		var list []Category

		for rows.Next() {
			var c Category
			rows.Scan(&c.ID, &c.Name, &c.Description)
			list = append(list, c)
		}

		json.NewEncoder(w).Encode(list)
		return
	}

	// CREATE
	if r.Method == "POST" {

		var c Category
		json.NewDecoder(r.Body).Decode(&c)

		_, err := db.Exec(
			"INSERT INTO categories(name,description) VALUES(?,?)",
			c.Name, c.Description,
		)

		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		json.NewEncoder(w).Encode(Response{
			Status:  "success",
			Message: "Category added",
		})

		return
	}

	http.Error(w, "Method not allowed", 405)
}

func categoryByIDHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	idStr := strings.TrimPrefix(r.URL.Path, "/categories/")
	id, _ := strconv.Atoi(idStr)

	// GET DETAIL
	if r.Method == "GET" {

		var c Category

		err := db.QueryRow(
			"SELECT id,name,description FROM categories WHERE id=?",
			id,
		).Scan(&c.ID, &c.Name, &c.Description)

		if err != nil {
			http.Error(w, "Data not found", 404)
			return
		}

		json.NewEncoder(w).Encode(c)
		return
	}

	// UPDATE
	if r.Method == "PUT" {

		var c Category
		json.NewDecoder(r.Body).Decode(&c)

		db.Exec(
			"UPDATE categories SET name=?, description=? WHERE id=?",
			c.Name, c.Description,
			id,
		)

		json.NewEncoder(w).Encode(Response{
			Status:  "success",
			Message: "Category updated",
		})

		return
	}

	// DELETE
	if r.Method == "DELETE" {

		db.Exec("DELETE FROM categories WHERE id=?", id)

		json.NewEncoder(w).Encode(Response{
			Status:  "success",
			Message: "Category deleted",
		})

		return
	}

	http.Error(w, "Method not allowed", 405)
}

func getCategoriesHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	rows, err := db.Query("SELECT id, name, description FROM categories")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var categories []Category

	for rows.Next() {

		var c Category

		err := rows.Scan(&c.ID, &c.Name, &c.Description)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		categories = append(categories, c)
	}

	json.NewEncoder(w).Encode(categories)
}

// ================= MIDDLEWARE JWT =================

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, "Token tidak ada", 401)
			return
		}

		tokenStr := strings.Replace(authHeader, "Bearer ", "", 1)

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Token tidak valid", 401)
			return
		}

		next(w, r)
	}
}

func transaksiHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var t Transaksi
	json.NewDecoder(r.Body).Decode(&t)

	// Ambil harga produk
	var harga int
	err := db.QueryRow(
		"SELECT harga FROM produk WHERE id=?",
		t.ProdukID,
	).Scan(&harga)

	if err != nil {
		http.Error(w, "Produk tidak ditemukan", 400)
		return
	}

	total := harga * t.Jumlah
	tanggal := time.Now().Format("2006-01-02")

	_, err = db.Exec(`
		INSERT INTO transaksi(produk_id,jumlah,total,tanggal)
		VALUES(?,?,?,?)
	`, t.ProdukID, t.Jumlah, total, tanggal)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	json.NewEncoder(w).Encode(Response{
		Status:  "success",
		Message: "Transaksi berhasil",
	})
}

func laporanHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
		SELECT tanggal, SUM(total) as omzet
		FROM transaksi
		GROUP BY tanggal
	`)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	type Laporan struct {
		Tanggal string `json:"tanggal"`
		Omzet   int    `json:"omzet"`
	}

	var list []Laporan

	for rows.Next() {

		var l Laporan
		rows.Scan(&l.Tanggal, &l.Omzet)

		list = append(list, l)
	}

	json.NewEncoder(w).Encode(list)
}

// ================= CORS =================

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}
