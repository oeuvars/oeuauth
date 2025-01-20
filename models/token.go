package models

import "gorm.io/gorm"

type Token struct {
	gorm.Model
	UserID    uint
	Token     string `gorm:"unique"`
	ExpiresAt int64
}
