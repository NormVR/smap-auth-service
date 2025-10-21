package postgres

import (
	domain_errors "auth-service/internal/domain/errors"
	"auth-service/internal/domain/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	db, err := sql.Open("pgx", storagePath)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return &Storage{db: db}, nil
}

// SaveUser saves a user into DB
func (s *Storage) SaveUser(
	ctx context.Context,
	email string,
	passHash []byte,
) (uuid.UUID, error) {
	var insertID uuid.UUID
	stmt, err := s.db.Prepare(`INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id`)

	if err != nil {
		return uuid.Nil, err
	}

	defer stmt.Close()

	id := uuid.New()

	res, err := stmt.QueryContext(ctx, id, email, string(passHash))
	if err != nil {
		var pgxErr *pgconn.PgError

		if errors.As(err, &pgxErr) && pgxErr.Code == "23505" {
			switch pgxErr.ConstraintName {
			case "users_email_key":
				return uuid.Nil, domain_errors.ErrUserEmailExists
			default:
				return uuid.Nil, fmt.Errorf("unknown unique constraint error: %w", err)
			}
		}

		return uuid.Nil, fmt.Errorf("failed to insert user: %w", err)
	}

	if res.Next() {
		err = res.Scan(&insertID)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to get last ID: %w", err)
		}
	}

	return insertID, err
}

// GetUser loads user auth data from DB
func (s *Storage) GetUser(ctx context.Context, email string) (*models.User, error) {
	stmt, err := s.db.PrepareContext(ctx, `SELECT id, email, password_hash FROM users WHERE email=$1`)

	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var user models.User
	err = stmt.QueryRowContext(ctx, email).Scan(
		&user.ID,
		&user.Email,
		&user.PassHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain_errors.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}
