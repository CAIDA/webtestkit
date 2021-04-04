package common

import "time"

type Config struct {
	CreateFilePrefix string
	BotConfigFile    string
	MongoConfigFile  string
	StartTime        time.Time
	Workers          int
	EnableMM         bool
}
