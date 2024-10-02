package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

// Modelo de usuário
type User struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `json:"email" gorm:"unique"`
	Password string `json:"-"`
}

func main() {
	// Configuração de conexão com o MySQL
	dsn := "root:@tcp(127.0.0.1:3306)/test?charset=utf8mb4&parseTime=True&loc=Local" // Sem senha
	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Não foi possível conectar ao banco de dados:", err)
	}

	// Migrar o modelo de usuário para a base de dados
	DB.AutoMigrate(&User{})

	r := gin.Default()

	// Rota para registro de usuário
	r.POST("/register", register)

	// Rota para login de usuário
	r.POST("/login", login)

	// Rota para listar todos os usuários (apenas nome)
	r.GET("/users", listUsers)

	r.Run(":8080") // Roda na porta 8080
}

// Função de registro
func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verifica se o email já existe
	var existingUser User
	if err := DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email já registrado"})
		return
	}

	// Hash da senha
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao criar senha"})
		return
	}
	user.Password = string(hashedPassword)

	// Salva o usuário no banco de dados
	if err := DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Usuário registrado com sucesso!"})
}

// Função de login
func login(c *gin.Context) {
	var loginData User
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := DB.Where("email = ?", loginData.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciais inválidas"})
		return
	}

	// Verifica a senha
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciais inválidas"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login realizado com sucesso!"})
}

// Função para listar todos os usuários (apenas o nome)
func listUsers(c *gin.Context) {
	var users []User
	DB.Select("name").Find(&users)

	c.JSON(http.StatusOK, users)
}
