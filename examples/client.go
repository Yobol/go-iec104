package main

import (
	"github.com/sirupsen/logrus"
	"github.com/yobol/go-iec104"
	"time"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	client := iec104.NewClient("172.16.251.22:6666", 10*time.Second, nil, logger)
	if err := client.Connect(); err != nil {
		panic(any(err))
	}
	defer client.Close()

	time.Sleep(30 * time.Second)
}
