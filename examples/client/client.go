package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/yobol/go-iec104"
	"time"
)

const (
	serverAddress = "172.16.251.22:6666"
	timeout       = 10 * time.Second
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	iec104.SetLogger(logger)

	client := iec104.NewClient(serverAddress, timeout, nil, func(apdu *iec104.APDU) {
		for _, signal := range apdu.Signals {
			fmt.Printf("%f ", signal.Value)
		}
		fmt.Println()
	})
	if err := client.Connect(); err != nil {
		panic(any(err))
	}
	defer client.Close()

	go func() {
		time.Sleep(5 * time.Second)
		client.SendTestFrame()
	}()

	go func() {
		time.Sleep(1 * time.Second)
		client.SendGeneralInterrogation()
	}()

	go func() {
		time.Sleep(2 * time.Second)
		client.SendCounterInterrogation()
	}()

	time.Sleep(30 * time.Minute)
}
