package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email      string `gorm:"unique;not null"`
	Password   string `json:"-"`
	OTP        string `json:"-"`
	OTPExpiry  int64
	IsVerified bool `gorm:"default:false"`
}
