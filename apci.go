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
	ApduLen uint8
	Cf1     byte
	Cf2     byte
	Cf3     byte
	Cf4     byte
}

/*
Parse is responsible for parsing control fields in APCI.
*/
func (apci *APCI) Parse() (byte, Frame, error) {
	switch {
	case apci.Cf1&0x1 == FrameTypeI:
		return FrameTypeI, apci.parseIFrame(), nil
	case apci.Cf1&0x3 == FrameTypeS:
		return FrameTypeS, apci.parseSFrame(), nil
	case apci.Cf1&0x3 == FrameTypeU:
		return FrameTypeU, apci.parseUFrame(), nil
	default:
		return 0xFF, nil, errors.New("unknown frame type")
	}
}

/*
parseIFrame is responsible for parsing IFrame from the control fields.
*/
func (apci *APCI) parseIFrame() *IFrame {
	send := int16(apci.Cf1)>>1 + int16(apci.Cf2)<<7
	recv := int16(apci.Cf3)>>1 + int16(apci.Cf4)<<7
	return &IFrame{
		SendSN: send,
		RecvSN: recv,
	}
}

/*
parseSFrame is responsible for parsing SFrame from the control fields.
*/
func (apci *APCI) parseSFrame() *SFrame {
	recv := int16(apci.Cf3)>>1 + int16(apci.Cf4)<<7
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
}

/*
IFrame (Information Transfer Format), last bit of CF1 is 0x0.

Control fields of I-format frame:
 | <-           8 bits            -> |
 | Send sequence no. N (S)       | 0 |
 | Send sequence no. N (S)           |
 | Receive sequence no. N (R)    | 0 |
 | Receive sequence no. N (R)        |

- It is used to preform numbered information transfer between the controlling and controlled station.
- I-format APDU always contains an ASDU. So It has variable length.
- Control fields of I-format indicate message direction. It contains two 15-bit sequence numbers that are sequentially
  increased by one for each APDU and each direction.

*/
type IFrame struct {
	SendSN int16
	RecvSN int16
}

func (i *IFrame) Type() FrameType {
	return FrameTypeI
}

/*
SFrame (), last two bit of CF1 is 0x10.

Control fields of S-format frame:
 | <-           8 bits            -> |
 |                           | 0 | 1 |
 |                                   |
 | Receive sequence no. N (R)    | 0 |
 | Receive sequence no. N (R)        |
*/
type SFrame struct {
	RecvSN int16
}

func (i *SFrame) Type() FrameType {
	return FrameTypeS
}

/*
UFrame (), last two bit of CF1 is 0x11.

Control fields of U-format frame:
 | <-           8 bits            -> |
 | TESTFR | STOPDT | STARTDT | 1 | 1 |
 |                                   |
 |                               | 0 |
 |                                   |

*/
type UFrame struct {
	Cmd []byte
}

func (i *UFrame) Type() FrameType {
	return FrameTypeU
}
