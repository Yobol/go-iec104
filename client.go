package iec104

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

type DataHandler func(apdu *APDU)

func NewClient(address string, timeout time.Duration, tc *tls.Config, h DataHandler) *Client {
	return &Client{
		address: address,
		tc:      tc,
		timeout: timeout,

		org: ORG(0),
		coa: COA(0x0001),

		sendChan: make(chan []byte, 1),
		recvChan: make(chan *APDU),
		dataChan: make(chan *APDU),

		dataHandler: h,
	}
}

// Client in IEC 104 is also called as master or controlling station.
type Client struct {
	address string      // address of the iec104 server
	tc      *tls.Config // whether we need secure network transmission using TLS
	conn    net.Conn    // network channel with the iec104 substation/server
	timeout time.Duration

	cancel      context.CancelFunc
	sendChan    chan []byte // send data to server
	recvChan    chan *APDU  // receive apdu from server
	dataChan    chan *APDU  // make Client owner to handle data received from server by themselves
	dataHandler DataHandler // the handler of data from received from server

	org      ORG    // originator address to identify controlling station when there are multiple controlling stations
	coa      COA    // common address (or station address)
	ssn, rsn uint16 // send sequence number, receive sequence number
	ifn      uint16 // i-format frame number (for send S-frame data regularity)
}

func (c *Client) Connect() error {
	if err := c.dial(); err != nil {
		return err
	}

	// After the establishment of a TCP connection, send and receive sequence number should be set to zero.
	c.ssn, c.rsn = 0, 0

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go c.writingToSocket(ctx)
	go c.readingFromSocket(ctx)
	go c.handlingData(ctx)

	c.sendUFrame(UFrameFunctionStartDTA)
	<-c.recvChan
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
	_lg.Info("start goroutine for writing to socket")
	defer func() {
		_lg.Info("stop goroutine for writing to socket")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.sendChan:
			if _, err := c.conn.Write(data); err != nil {
				_lg.Errorf("write to socket: %s", err.Error())
			}
		}
	}
}
func (c *Client) readingFromSocket(ctx context.Context) {
	_lg.Info("start goroutine for reading from socket")
	defer func() {
		_lg.Info("stop goroutine for reading from socket")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			apdu, err := c.readFromSocket(ctx)
			if err != nil {
				_lg.Errorf("read from socket: %v", err)
				time.Sleep(1 * time.Second)
				break
			}

			switch apdu.frame.Type() {
			case FrameTypeU:
				uFrame, ok := apdu.frame.(*UFrame)
				if ok {
					switch uFrame.Cmd[0] {
					case UFrameFunctionStartDTA[0]:
						_lg.Debugf("receive u frame: StartDTA")
					case UFrameFunctionStartDTC[0]:
						_lg.Debugf("receive u frame: StartDTC")
						c.recvChan <- apdu
					case UFrameFunctionStopDTA[0]:
						_lg.Debugf("receive u frame: StopDTA")
					case UFrameFunctionStopDTC[0]:
						_lg.Debugf("receive u frame: StopDTC")
						c.recvChan <- apdu
					case UFrameFunctionTestFA[0]:
						_lg.Debugf("receive u frame: TestFA")
						c.sendUFrame(UFrameFunctionTestFC)
					case UFrameFunctionTestFC[0]:
						_lg.Debugf("receive u frame: TestFC")
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

func (c *Client) handlingData(ctx context.Context) {
	_lg.Info("start goroutine for handling data received from server")
	defer func() {
		_lg.Info("stop goroutine for handling data received from server")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case aspu := <-c.dataChan:
			_lg.Debugf("handle data: TypeID: %X, COT: %X", aspu.ASDU.typeID, aspu.ASDU.cot)
			go c.dataHandler(aspu)
		}
	}
}

// readApduHeader reads both startByte and apduLen, and returns apduLen
func (c *Client) readApduHeader() (uint8, error) { //
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
	return buf[1], nil
}
func (c *Client) readApduBody(apduLen uint8) (*APDU, error) {
	apduData := make([]byte, apduLen)
	n, err := c.conn.Read(apduData)
	if err != nil {
		return nil, err
	}
	for n < int(apduLen) {
		bufLen := int(apduLen) - n
		buf := make([]byte, bufLen)
		m, err := c.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		apduData = append(apduData[:n], buf[:m]...)
		n = len(apduData)
	}
	_lg.Debugf("receive: [% X]", append([]byte{startByte, apduLen}, apduData...))

	apdu := new(APDU)
	if err := apdu.Parse(apduData); err != nil {
		return nil, err
	}

	switch apdu.frame.Type() {
	case FrameTypeI:
		if apdu.ASDU.toBeHandled {
			c.dataChan <- apdu
		}
		if apdu.ASDU.sendSFrame {
			c.SendTestFrame()
		}

		c.incRsn()
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

func (c *Client) SendGeneralInterrogation() {
	ios := []*InformationObject{
		{
			ioa: 0x000000,
			ies: []*InformationElement{
				{
					Format: []InformationElementType{QOI},
					Raw:    []byte{0x14},
				},
			},
		},
	}
	c.SendIFrame(&ASDU{
		typeID: CIcNa1,
		sq:     false,
		nObjs:  NOO(len(ios)),
		t:      false,
		cot:    CotAct,
		ios:    ios,
	})
}

func (c *Client) SendCounterInterrogation() {
	ios := []*InformationObject{
		{
			ioa: 0x000000,
			ies: []*InformationElement{
				{
					Format: []InformationElementType{QCC},
					Raw:    []byte{0x45},
				},
			},
		},
	}
	c.SendIFrame(&ASDU{
		typeID: CCiNa1,
		sq:     false,
		nObjs:  NOO(len(ios)),
		t:      false,
		cot:    CotAct,
		ios:    ios,
	})
}

func (c *Client) SendIFrame(asdu *ASDU) {
	apci := &IFrame{
		SendSN: c.ssn,
		RecvSN: c.rsn,
	}
	asdu.org = c.org
	asdu.coa = c.coa
	c.sendIFrame(apci, asdu)
}

func (c *Client) sendIFrame(apci *IFrame, asdu *ASDU) {
	c.incSsn()

	frame := c.buildFrame(append(apci.Data(), asdu.Data()...))
	_lg.Debugf("send i frame: [% X]", frame)
	c.sendChan <- frame
}

func (c *Client) SendTestFrame() {
	c.sendSFrame(&SFrame{
		RecvSN: c.rsn,
	})
}
func (c *Client) sendSFrame(x *SFrame) {
	frame := c.buildFrame(x.Data())
	_lg.Debugf("send s frame: [% X]", frame)
	c.sendChan <- frame
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
	_lg.Debugf("send u frame: %s - [% X]", name, frame)
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

func (c *Client) incRsn() {
	c.rsn++
	if c.rsn == 1<<15 {
		c.rsn = 0
	}
}

func (c *Client) incSsn() {
	c.ssn++
	if c.rsn == 1<<15 {
		c.ssn = 0
	}
}
