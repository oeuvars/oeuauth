// migrations/migrate.go
package migrations

import (
	"auth/models"
	"log"

	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) {
	log.Println("Running database migrations...")

	// Add all your models here
	err := db.AutoMigrate(
		&models.User{},
		&models.Token{},
	)

	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	log.Println("Database migration completed successfully!")
}
