package model

import "time"

type Task struct {
	ID        uint      `json:"id" gorm:"primary_key"`
	Title     string    `json:"title" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	User      User      `json:"user" gorm:"foreignkey:UserID; constraint:OnDelete:CASCADE"`
	UserID    uint      `json:"user_id"`
}

type TaskResponse struct {
	ID        uint      `json:"id" goem:"primary_key"`
	Title     string    `json:"title" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
