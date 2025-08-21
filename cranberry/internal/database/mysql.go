package database

import (
	"cranberry/internal/config"
	"cranberry/internal/logging"
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type MysqlConnection struct {
	logger        logging.ILogger
	configuration config.Configuration
	db            *gorm.DB
}

func NewMysqlConnection(logger logging.ILogger, configuration config.Configuration) *MysqlConnection {
	return &MysqlConnection{logger: logger, configuration: configuration}
}

func (mc *MysqlConnection) createTables() error {
	err := mc.db.AutoMigrate(&Proxy{})
	if err != nil {
		return err
	}

	return nil
}

func (mc *MysqlConnection) Init() error {
	//Extract the username, password, IP and port from the configuration
	sqlUsername := mc.configuration.DBOptions.SqlOptions.Username
	sqlPassword := mc.configuration.DBOptions.SqlOptions.Password
	sqlIP := mc.configuration.DBOptions.SqlOptions.IP
	sqlPort := mc.configuration.DBOptions.SqlOptions.Port
	sqlDatabase := mc.configuration.DBOptions.SqlOptions.Database

	sqlURL := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8&parseTime=True&loc=Local", sqlUsername, sqlPassword, sqlIP, sqlPort, sqlDatabase)

	//Connect to mysql from the configuration
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                       sqlURL, // data source name
		DefaultStringSize:         256,    // default size for string fields
		DisableDatetimePrecision:  true,   // disable datetime precision, which not supported before MySQL 5.6
		DontSupportRenameIndex:    true,   // drop & create when rename index, rename index not supported before MySQL 5.7, MariaDB
		DontSupportRenameColumn:   true,   // `change` when rename column, rename column not supported before MySQL 8, MariaDB
		SkipInitializeWithVersion: false,  // auto configure based on currently MySQL version
	}), &gorm.Config{})

	//Check if an error occured during the connection initialization
	if err != nil {
		return err
	}

	//Save the db inside the structure
	mc.db = db

	//Create the tables based on the models
	err = mc.createTables()
	if err != nil {
		mc.logger.Error("Failed to create tables", err.Error())
		return err
	}

	return nil
}
