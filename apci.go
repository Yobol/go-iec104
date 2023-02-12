package iec104

import (
	"errors"
)

const startByte = 0x68

/*
APCI (Application Protocol Control Information).

Each APCI starts with a start byte with value 0x68 followed by the 8-bit
length of APDU and four 8-bit control fields (CF). Generally, the length of APCI is 6 bytes.

  | <-   8 bits    -> |  -----
  | Start Byte (Ox68) |    |
  | Length of APDU    |    |
  | Control Field 1   |   APCI
  | Control Field 2   |    |
  | Control Field 3   |    |
  | Control Field 4   |    |
  | <-   8 bits    -> |  -----
*/
type APCI struct {
	// StartByte byte
	// ApduLen uint8
	Cf1 byte
	Cf2 byte
	Cf3 byte
	Cf4 byte
}

/*
Parse is responsible for parsing control fields in APCI.
*/
func (apci *APCI) Parse(data []byte) (Frame, error) {
	apci.Cf1 = data[0]
	apci.Cf2 = data[1]
	apci.Cf3 = data[2]
	apci.Cf4 = data[3]

	switch {
	case apci.Cf1&0x1 == FrameTypeI:
		return apci.parseIFrame(), nil
	case apci.Cf1&0x3 == FrameTypeS:
		return apci.parseSFrame(), nil
	case apci.Cf1&0x3 == FrameTypeU:
		return apci.parseUFrame(), nil
	default:
		return nil, errors.New("unknown frame type")
	}
}

/*
parseIFrame is responsible for parsing IFrame from the control fields.
*/
func (apci *APCI) parseIFrame() *IFrame {
	send := uint16(apci.Cf1>>1 | apci.Cf2<<7)
	recv := uint16(apci.Cf3>>1 | apci.Cf4<<7)
	return &IFrame{
		SendSN: send,
		RecvSN: recv,
	}
}

/*
parseSFrame is responsible for parsing SFrame from the control fields.
*/
func (apci *APCI) parseSFrame() *SFrame {
	recv := uint16(apci.Cf3>>1 | apci.Cf4<<7)
	return &SFrame{
		RecvSN: recv,
	}
}

/*
parseUFrame is responsible for parsing UFrame from the control fields.
*/
func (apci *APCI) parseUFrame() *UFrame {
	cmd := []byte{apci.Cf1, apci.Cf2, apci.Cf3, apci.Cf4}
	return &UFrame{
		Cmd: cmd,
	}
}

/*
FrameType is the transmission frame format.

The frame format is determined by the two last bits of the first control field (CF1).
*/
type FrameType = byte // transmission frame format

const (
	FrameTypeI FrameType = iota
	FrameTypeS
	FrameTypeU FrameType = iota + 1
)

type UFrameFunction []byte

var (
	UFrameFunctionStartDTA UFrameFunction = []byte{0x07, 0x00, 0x00, 0x00} // Start Data Transfer Activation   CF1: 0 0 0 0 0 1 | 1 1
	UFrameFunctionStartDTC UFrameFunction = []byte{0x0B, 0x00, 0x00, 0x00} // Start Data Transfer Confirmation CF1: 0 0 0 0 1 0 | 1 1
	UFrameFunctionStopDTA  UFrameFunction = []byte{0x13, 0x00, 0x00, 0x00} // Stop Data Transfer Activation    CF1: 0 0 0 1 0 0 | 1 1
	UFrameFunctionStopDTC  UFrameFunction = []byte{0x23, 0x00, 0x00, 0x00} // Stop Data Transfer Confirmation  CF1: 0 0 1 0 0 0 | 1 1
	UFrameFunctionTestFA   UFrameFunction = []byte{0x43, 0x00, 0x00, 0x00} // Test Frame Activation            CF1: 0 1 0 0 0 0 | 1 1
	UFrameFunctionTestFC   UFrameFunction = []byte{0x83, 0x00, 0x00, 0x00} // Test Frame Confirmation          CF1: 1 0 0 0 0 0 | 1 1
)

type Frame interface {
	Type() FrameType
	Data() []byte
}

/*
IFrame (Information Transfer Format), last bit of CF1 is (0)B.

Control fields of I-format frame:
 | <-              8 bits              -> |
 | Send sequence no. N(S)     [LSB]   | 0 |
 | Send sequence no. N(S)     [MSB]       |
 | Receive sequence no. N(R)  [LSB]   | 0 |
 | Receive sequence no. N(R)  [MSB]       |

- It is used to preform numbered information transfer between the controlling and controlled station.
- I-format APDUs always contain an ASDU, so it has variable length.
- Control fields of I-format indicate message direction. It contains two 15-bit sequence numbers that are sequentially
  increased by one for each APDU and each direction.
  - The sender increases the send sequence number N(S) and the receiver increases the receive sequence number N(S).
    The receiving station acknowledges each APDU or a number of APDUs when it returns the receive sequence number
    up to the number whose APDUs are properly received.
  - The sending station holds the APDU or APDUs in a buffer until it receives back its own send sequence number as a
    receive sequence number which is valid acknowledge for all numbers less or equal to the received number.
  - In case of a longer data transmission in one direction only, an S format has to be sent in the other direction to
    acknowledge the APDUs before buffer overflow or time out.
  - The method should be used in both directions. After the establishment of a TCP connection, the send and receive
    sequence numbers are set to zero.
- The right interpretation of sequence numbers depends on the position of LSB (the Least Significant Bit) and
  MSB (the Most Significant Bit).
  - N(S) = CF1 >> 1 + CF2 << 7
  - N(R) = CF3 >> 1 + CF4 << 7
  For example, CRs 0x06 Ox00 0x02 0x00 will be interpreted as N(S) = 3 and N(R) = 1,
  e.g., the third APDU send by the source and waiting for the first APDU from the destination.
*/
type IFrame struct {
	APCI
	SendSN uint16
	RecvSN uint16
}

func (i *IFrame) Type() FrameType {
	return FrameTypeI
}

func (i *IFrame) Data() []byte {
	sBytes, rBytes := serializeLittleEndianUint16(i.SendSN<<1), serializeLittleEndianUint16(i.RecvSN<<1)
	return []byte{sBytes[0], sBytes[1], rBytes[0], rBytes[1]}
}

/*
SFrame (Numbered Supervisory functions), last two bit of CF1 is (01)B.

Control fields of S-format frame:
 | <-              8 bits              -> |
 |                                | 0 | 1 |
 |                                        |
 | Receive sequence no. N(R)  [LSB]   | 0 |
 | Receive sequence no. N(R)  [MSB]       |

- It is used to perform numbered supervisory functions.
- S-format APDUs always consist of one APCI only, so it has fixed length.
- In any cases where the data transfer is only in a single direction, S-format APDUs have to be sent in other direction
  before timeout, buffer overflow or when it has crossed maximum number of allowed I-format APDUs without acknowledgement.
*/
type SFrame struct {
	APCI
	RecvSN uint16
}

func (s *SFrame) Type() FrameType {
	return FrameTypeS
}

func (s *SFrame) Data() []byte {
	return []byte{byte(0b1), byte(0b0), byte(s.RecvSN & 0b01111111), byte(s.RecvSN >> 7)}
}

/*
UFrame (Unnumbered control functions), last two bit of CF1 is (11)B.

Control fields of U-format frame:
 | <-              8 bits              -> |
 | TESTFR  |  STOPDT  |  STARTDT  | 1 | 1 |
 |                                        |
 |                                    | 0 |
 |                                        |
 |                                    | 0 |

- It is used to perform unnumbered control functions. To be specific, it is used for activation and confirmation
  mechanism of STARTDT, STOPDT and TESTFR. Only one of functions TESTFR/STOPDT/STARTDT can be activated at the same time.
- U-format APDUs always contain one APCI only, so it has fixed length.
- STARTDT, and STOPDT are used by the controlling station to control the data transfer from a controlled station.
  - When the connection is established, user data transfer is not automatically enabled, e.g., default state is STOPDT.
    In this state, the controlled station does not send any data via this connection, except unnumbered control functions
    and confirmations. The controlling station must activate the user data transfer by sending a STARTDT act (activate).
    The controlled station responds with a STARTDT con (confirm). If the STARTDT is not confirmed, the connection is
    closed by the controlling station. TODO 给 STARTDT ACTIVATE 设置确认超时！！！
  - Only the controlling station sends the STARTDT. The expected mode of operation is that the STARTDT is sent only
    once after the initial establishment of the connection. The connection then operates with both controlled and
    controlling station permitted to send any messages at any time until the controlling station decides to close
    the connection with a STOPDT command.
- The controlling and/or controlled station must regularly check the status of all established connections to detect
  any communication problems as soon as possible. This is done by sending TESTFR frames.
  - Open connections may be periodically tested in both directions by sending test APDUs (TESTFR=act) which are confirmed
    by the receiving station sending TESTFR=con.
  - Both stations may initiate the test procedure after a specific period of time in which no data transfer occur (timeout).
    TODO 主站向子站发送 TESTFR=act 等待子站响应 TESTFR=con。
*/
type UFrame struct {
	APCI
	Cmd []byte
}

func (u *UFrame) Type() FrameType {
	return FrameTypeU
}

func (u *UFrame) Data() []byte {
	return u.Cmd
}
