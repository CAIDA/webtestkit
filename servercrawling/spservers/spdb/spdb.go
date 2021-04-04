package spdb

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	speedtestmongo = "mongodb://localhost:27017"
	colserver      = "speedserver"
)

type SpeedtestMongo struct {
	config   *DBConfig
	Client   *mongo.Client
	Database *mongo.Database
}

type DBConfig struct {
	Username string
	Password string
	AuthDB   string
	DB       string
}

func connectmongo(mongopath, dbname string) (*mongo.Client, *mongo.Database) {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongopath))
	if err != nil {
		log.Panic(err)
		return nil, nil
	}
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Panic(err)
		return nil, nil
	}
	log.Println("Database connected")
	return client, client.Database(dbname)
}

func (cm *SpeedtestMongo) Close() {
	if cm.Client != nil {
		err := cm.Client.Disconnect(context.TODO())
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Database connection ends")
	} else {
		log.Println("Mongo clientt is nil")
	}
}

func NewMongoDB(config string, dbname string) *SpeedtestMongo {
	cfile, err := os.Open(config)
	defer cfile.Close()
	if err != nil {
		log.Panic(err)
		return nil
	}
	c := &SpeedtestMongo{}
	decoder := json.NewDecoder(cfile)
	c.config = &DBConfig{}
	err = decoder.Decode(c.config)
	if err != nil {
		log.Panic(err)
		return nil
	}
	mongostr := "mongodb://"
	if c.config.DB == "" {
		log.Fatal("no database was selected")
	}
	if c.config.Username != "" && c.config.Password != "" {
		mongostr = mongostr + c.config.Username + ":" + c.config.Password + "@" + c.config.DB
		if c.config.AuthDB != "" {
			mongostr = mongostr + "/?authSource=" + c.config.AuthDB
		}
	}
	log.Println(mongostr)
	c.Client, c.Database = connectmongo(mongostr, dbname)
	return c
}

func (cm *SpeedtestMongo) ResetEnable(servertype string) {
	if cm.Database != nil {
		cspeed := cm.Database.Collection(colserver)
		filter := bson.D{{"type", servertype}}
		update := bson.D{{"$set", bson.D{{"enabled", false}}}}
		res, err := cspeed.UpdateMany(context.TODO(), filter, update)
		if err != nil {
			log.Fatal(err)
		}
		if res.MatchedCount > 0 {
			log.Println("Distabled", res.MatchedCount, servertype, "servers")
		}
	}
}

func (cm *SpeedtestMongo) InsertServers(servers []SpeedServer) (int, error) {
	if cm.Database != nil && len(servers) > 0 {
		nodoc := 0
		cspeed := cm.Database.Collection(colserver)
		opt := options.FindOneAndReplace().SetUpsert(true)
		for _, ser := range servers {
			filter := bson.D{{"type", ser.Type}, {"id", ser.Id}}
			res := cspeed.FindOneAndReplace(context.TODO(), filter, ser, opt)
			if res.Err() != nil {
				if res.Err() == mongo.ErrNoDocuments {
					nodoc++
					//	log.Println("Server not found", ser.Type, ser.Id)
				} else {
					log.Fatal(res.Err())
				}
			}
		}

		return nodoc, nil
	}
	if cm.Database == nil {
		return 0, errors.New("Database is nil")
	}
	return 0, nil
}
