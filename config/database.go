// config/database.go
package config

import (
	"crypto/x509"
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func LoadCACert(path string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	return certPool, nil
}

func ConnectDB() (*gorm.DB, error) {
	// Load CA certificate

	// Construct DSN with SSL mode and other parameters
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=verify-full sslrootcert=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
		os.Getenv("CA_CERT_PATH"),
	)

	// Open database connection with custom TLS config
	config := postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true,
		WithoutReturning:     false,
	}

	return gorm.Open(postgres.New(config), &gorm.Config{})
}
