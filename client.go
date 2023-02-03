package iec104

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

func NewClient(address string, timeout time.Duration, tc *tls.Config, lg *logrus.Logger) *Client {
	return &Client{
		address: address,
		tc:      tc,
		timeout: timeout,

		sendChan: make(chan []byte, 1),
		recvChan: make(chan *APDU),
		lg:       lg,
	}
}

// Client in IEC 104 is also called master or controlling station.
// Server in IEC 104 is also called slave or controlled station.
type Client struct {
	address string      // address of the iec104 server
	tc      *tls.Config // whether we need secure network transmission using TLS
	conn    net.Conn    // network channel with the iec104 substation/server
	timeout time.Duration

	cancel   context.CancelFunc
	sendChan chan []byte // send data to server
	recvChan chan *APDU  // receive apdu from server

	ssn, rsn int // send sequence number, receive sequence number
	ifn      int // i-format frame number

	lg *logrus.Logger // logger
}

func (c *Client) Connect() error {
	if err := c.dial(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go c.writingToSocket(ctx)
	go c.readingFromSocket(ctx)

	c.sendUFrame(UFrameFunctionStartDTA)
	<-c.recvChan // receive: StartDTC

	return nil
}
func (c *Client) dial() (err error) {
	var conn net.Conn
	if c.tc != nil {
		conn, err = tls.Dial("tcp", c.address, c.tc)
	} else {
		conn, err = net.Dial("tcp", c.address)
	}
	if err != nil {
		return err
	}
	c.conn = conn
	return
}

func (c *Client) writingToSocket(ctx context.Context) {
	c.lg.Info("start goroutine for writing to socket")
	defer func() {
		c.lg.Info("stop goroutine for writing to socket")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.sendChan:
			if _, err := c.conn.Write(data); err != nil {
				c.lg.Errorf("write to socket: %s", err.Error())
			}
		}
	}
}
func (c *Client) readingFromSocket(ctx context.Context) {
	c.lg.Info("start goroutine for reading from socket")
	defer func() {
		c.lg.Info("stop goroutine for reading from socket")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			apdu, err := c.readFromSocket(ctx)
			if err != nil {
				c.lg.Errorf("read from socket: %v", err)
				time.Sleep(1 * time.Second)
				break
			}

			ft, frame, err := apdu.APCI.Parse()
			if err != nil {
				c.lg.Errorf("parse apci: %v", err)
				break
			}
			switch ft {
			case FrameTypeU:
				uFrame, ok := frame.(*UFrame)
				if ok {
					switch uFrame.Cmd[0] {
					case UFrameFunctionStartDTA[0]:
						c.lg.Debugf("receive u frame: StartDTA")
					case UFrameFunctionStartDTC[0]:
						c.lg.Debugf("receive u frame: StartDTC")
						c.recvChan <- apdu
					case UFrameFunctionStopDTA[0]:
						c.lg.Debugf("receive u frame: StopDTA")
					case UFrameFunctionStopDTC[0]:
						c.lg.Debugf("receive u frame: StopDTC")
						c.recvChan <- apdu
					case UFrameFunctionTestFA[0]:
						c.lg.Debugf("receive u frame: TestFA")
						c.sendUFrame(UFrameFunctionTestFC)
					case UFrameFunctionTestFC[0]:
						c.lg.Debugf("receive u frame: TestFC")
						c.sendUFrame(UFrameFunctionTestFC)
					}
				}
			}
		}
	}
}
func (c *Client) readFromSocket(ctx context.Context) (*APDU, error) {
	apduLen, err := c.readApduHeader()
	if err != nil {
		return nil, err
	}
	// c.conn.SetDeadline(time.Now().Add(c.timeout))

	apdu, err := c.readApduBody(apduLen)
	if err != nil {
		return nil, err
	}
	return apdu, nil
}

// readApduHeader reads both startByte and apduLen, and returns apduLen
func (c *Client) readApduHeader() (int, error) { //
	buf := make([]byte, 2)

	n, err := c.conn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n != 2 {
		return 0, errors.New("invalid data: empty")
	} else if buf[0] != startByte {
		return 0, fmt.Errorf("invalid data: unexpected start - % X, expected start - % X", buf[0], startByte)
	}
	return int(buf[1]), nil
}
func (c *Client) readApduBody(apduLen int) (*APDU, error) {
	apduData := make([]byte, apduLen)
	n, err := c.conn.Read(apduData)
	if err != nil {
		return nil, err
	}
	for n < apduLen {
		bufLen := apduLen - n
		buf := make([]byte, bufLen)
		m, err := c.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		apduData = append(apduData[:n], buf[:m]...)
		n = len(apduData)
	}

	apdu := new(APDU)
	if err := apdu.Parse(apduData); err != nil {
		return nil, err
	}
	return apdu, nil
}

func (c *Client) IsConnected() bool {
	panic(any("implement me"))
	return false
}

func (c *Client) Close() {
	c.sendUFrame(UFrameFunctionStopDTA)
	<-c.recvChan // receive StopDTC

	if c.cancel != nil {
		c.cancel()
	}
}

func (c *Client) sendIFrame() {
	panic(any("implement me"))

	//frame := c.buildFrame()
	//c.lg.Debugf("send i frame: [% X]", frame)
	//c.sendChan <- frame
}

func (c *Client) sendSFrame() {
	panic(any("implement me"))

	//frame := c.buildFrame()
	//c.lg.Debugf("send s frame: [% X]", frame)
	//c.sendChan <- frame
}

func (c *Client) sendUFrame(x UFrameFunction) {
	name := ""
	frame := c.buildFrame(x)
	switch x[0] {
	case UFrameFunctionStartDTA[0]:
		name = "StartDTA"
	case UFrameFunctionStartDTC[0]:
		name = "StartDTC"
	case UFrameFunctionStopDTA[0]:
		name = "StopDTA"
	case UFrameFunctionStopDTC[0]:
		name = "StopDTC"
	case UFrameFunctionTestFA[0]:
		name = "TestFA"
	case UFrameFunctionTestFC[0]:
		name = "TestFC"
	}
	c.lg.Debugf("send u frame: %s - [% X]", name, frame)
	c.sendChan <- frame
}

func (c *Client) buildFrame(data []byte) []byte {
	frame := make([]byte, 0, 0)
	iBytes := serializeBigEndianUint16(uint16(len(data)))
	frame = append(frame, startByte)
	frame = append(frame, iBytes[1])
	frame = append(frame, data...)
	return frame
}

func serializeBigEndianUint16(i uint16) []byte {
	bytes := make([]byte, 2, 2)
	binary.BigEndian.PutUint16(bytes, i)
	return bytes
}
