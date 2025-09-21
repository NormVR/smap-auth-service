package models

type User struct {
	ID        int64  `db:"id"`
	Email     string `db:"email"`
	Username  string `db:"username"`
	FirstName string `db:"firstname"`
	LastName  string `db:"lastname"`
	PassHash  []byte `db:"pass_hash"`
}
