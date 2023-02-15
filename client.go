package iec104

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

func NewClient(option *ClientOption) *Client {
	return &Client{
		ClientOption: option,

		org: ORG(0),
		coa: COA(0x0001),

		sendChan:   make(chan []byte, 1),
		recvChan:   make(chan *APDU),
		dataChan:   make(chan *APDU),
		cmdRspChan: make(chan *cmdRsp, 0),
	}
}

// Client in IEC 104 is also called as master or controlling station.
type Client struct {
	*ClientOption
	conn net.Conn // network channel with the iec104 substation/server

	cancel     context.CancelFunc
	sendChan   chan []byte // send data to server
	recvChan   chan *APDU  // receive apdu from server
	dataChan   chan *APDU  // make Client owner to handle data received from server by themselves
	cmdRspChan chan *cmdRsp

	org      ORG    // originator address to identify controlling station when there are multiple controlling stations
	coa      COA    // common address (or station address)
	ssn, rsn uint16 // send sequence number, receive sequence number
	ifn      uint16 // i-format frame number (for send S-frame data regularity)

	status int32 // initial, connected, disconnected
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

	c.onConnectHandler(c)
	return nil
}
func (c *Client) dial() (err error) {
	schema, address, timeout := c.server.Scheme, c.server.Host, c.connectTimeout
	var conn net.Conn
	switch schema {
	case "tcp":
		conn, err = net.DialTimeout("tcp", address, timeout)
	case "ssl", "tls", "tcps":
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", address, c.tc)
	default:
		return fmt.Errorf("unknown schema: %s", schema)
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
				panic(any(fmt.Errorf("read from socket: %v", err)))
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
		case apdu := <-c.dataChan:
			if err := c.handleData(apdu); err != nil {
				_lg.Warnf("handle iFrame, got: %v", err)
			}
		}
	}
}
func (c *Client) handleData(apdu *APDU) error {
	defer func() {
		if err := recover(); err != nil {
			_lg.Errorf("client handler: %+v", err)
		}
	}()

	_lg.Debugf("handle iFrame: TypeID: %X, COT: %X", apdu.ASDU.typeID, apdu.ASDU.cot)

	switch apdu.typeID {
	case CIcNa1:
		return c.handler.GeneralInterrogationHandler(apdu)
	case CCiNa1:
		return c.handler.CounterInterrogationHandler(apdu)
	case CRdNa1:
		return c.handler.ReadCommandHandler(apdu)
	case CCsNa1:
		return c.handler.ClockSynchronizationHandler(apdu)
	case CTsNb1, CTsTa1:
		return c.handler.TestCommandHandler(apdu)
	case CRpNc1:
		return c.handler.ResetProcessCommandHandler(apdu)
	case CCdNa1:
		return c.handler.DelayAcquisitionCommandHandler(apdu)
	default:
		return c.handler.APDUHandler(apdu)
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
		if apdu.ASDU.cmdRsp != nil {
			c.cmdRspChan <- apdu.ASDU.cmdRsp
		}
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
	return true
}

func (c *Client) Close() {
	c.onDisconnectHandler(c)

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

func (c *Client) SendSingleCommand(address IOA, close bool) error {
	// select
	ie := &InformationElement{
		Format: []InformationElementType{SCO},
	}
	if close {
		ie.Raw = []byte{0x81}
	} else {
		ie.Raw = []byte{0x80}
	}
	ios := []*InformationObject{
		{
			ioa: address,
			ies: []*InformationElement{ie},
		},
	}
	c.SendIFrame(&ASDU{
		typeID: CScNa1,
		sq:     false,
		nObjs:  NOO(len(ios)),
		t:      false,
		cot:    CotAct,
		ios:    ios,
	})
	select {
	case rsp := <-c.cmdRspChan:
		if rsp.err != nil {
			return rsp.err
		}
	}

	// execute
	ie = &InformationElement{
		Format: []InformationElementType{SCO},
	}
	if close {
		ie.Raw = []byte{0x01}
	} else {
		ie.Raw = []byte{0x00}
	}
	ios = []*InformationObject{
		{
			ioa: address,
			ies: []*InformationElement{ie},
		},
	}
	c.SendIFrame(&ASDU{
		typeID: CScNa1,
		sq:     false,
		nObjs:  NOO(len(ios)),
		t:      false,
		cot:    CotAct,
		ios:    ios,
	})
	select {
	case rsp := <-c.cmdRspChan:
		if rsp.err != nil {
			return rsp.err
		}
	}
	return nil
}

func (c *Client) SendDoubleCommand(address IOA, close bool) error {
	ie := &InformationElement{
		Format: []InformationElementType{DCO},
	}
	if close {
		ie.Raw = []byte{0x82}
	} else {
		ie.Raw = []byte{0x81}
	}
	ios := []*InformationObject{
		{
			ioa: address,
			ies: []*InformationElement{ie},
		},
	}
	c.SendIFrame(&ASDU{
		typeID: CDcNa1,
		sq:     false,
		nObjs:  NOO(len(ios)),
		t:      false,
		cot:    CotAct,
		ios:    ios,
	})

	select {
	case rsp := <-c.cmdRspChan:
		if rsp.err != nil {
			return rsp.err
		}
	}

	// execute
	ie = &InformationElement{
		Format: []InformationElementType{DCO},
	}
	if close {
		ie.Raw = []byte{0x02}
	} else {
		ie.Raw = []byte{0x01}
	}
	ios = []*InformationObject{
		{
			ioa: address,
			ies: []*InformationElement{ie},
		},
	}
	c.SendIFrame(&ASDU{
		typeID: CDcNa1,
		sq:     false,
		nObjs:  NOO(len(ios)),
		t:      false,
		cot:    CotAct,
		ios:    ios,
	})

	select {
	case rsp := <-c.cmdRspChan:
		if rsp.err != nil {
			return rsp.err
		}
	}
	return nil
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
