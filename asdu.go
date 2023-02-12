package iec104

import (
	"encoding/binary"
	"fmt"
)

/*
ASDU (Application Service Data Unit).

The ASDU contains two main sections:
- the data unit identifier (with the fixed length of six bytes):
  - defining the specific type of data;
  - providing addressing to identify the specific data;
  - including information as cause of transmission.
- the data itself, made up of one or more information objects:
  - each ASDU can transmit maximum 127 objects;
  - the type identification is applied to the entire ASDU, so the information objects contained in the ASDU
    are of the same type.

The format of ASDU:
 | <-              8 bits              -> |
 | Type Identification                    |  --------------------
 | SQ | Number of objects                 |           |
 | T  | P/N | Cause of transmission (COT) |           |
 | Original address (ORG)                 |  Data Uint Identifier
 | ASDU address fields                    |           |
 | ASDU address fields                    |  --------------------
 | Information object address (IOA)       |  --------------------
 | Information object address (IOA)       |           |
 | Information object address (IOA)       |  Information Object 1
 | Information Elements                   |           |
 | Time Tag                               |  --------------------
 | Information Object 2                   |
 | Information Object N                   |

*/
type ASDU struct {
	// Data Uint Identifier(with the fixed length of 6 bytes)
	typeID TypeID // 8  bits
	sq     SQ     // 1  bit
	nObjs  NOO    // 7  bits
	t      T      // 1  bit
	pn     PN     // 1  bit
	cot    COT    // 6  bits
	org    ORG    // 8  bits
	coa    COA    // 16 bits

	ios     []*InformationObject
	Signals []*InformationElement
}

func (asdu *ASDU) Parse(data []byte) error {
	// I-format frame have ASDU.
	if len(data) < AsduHeaderLen {
		return fmt.Errorf("invalid asdu header: % X", data)
	}

	// the 1st byte
	asdu.parseTypeID(data[0])
	// the 2nd byte
	asdu.parseSQ(data[1])
	asdu.parseNOO(data[1])
	// the 3rd byte
	asdu.parseT(data[2])
	asdu.parsePN(data[2])
	asdu.parseCOT(data[2])
	// the 4th byte
	asdu.parseORG(data[3])
	// the 5th and 6th bytes
	asdu.parseCOA(data[4:AsduHeaderLen])

	asdu.parseInformationObjects(data[AsduHeaderLen:])
	return nil
}

func (asdu *ASDU) Data() []byte {
	data := make([]byte, 0)
	// the 1st byte
	data = append(data, byte(asdu.typeID))
	// the 2nd byte
	data = append(data, func() byte {
		if asdu.sq {
			return (0b1 << 7) & asdu.nObjs
		} else {
			return asdu.nObjs
		}
	}())
	// the 3rd byte
	data = append(data, func() byte {
		if bool(asdu.t) && bool(asdu.pn) {
			return (0b11 << 6) & byte(asdu.cot)
		} else if asdu.t {
			return (0b1 << 7) & byte(asdu.cot)
		} else if asdu.pn {
			return (0b1 << 6) & byte(asdu.cot)
		} else {
			return byte(asdu.cot)
		}
	}())
	// the 4th byte
	data = append(data, byte(asdu.org))
	// the 5th and 6th bytes
	data = append(data, func() []byte {
		x := make([]byte, 2, 2)
		binary.LittleEndian.PutUint16(x, asdu.coa)
		return x
	}()...)

	// the remaining bytes (some information objects)
	data = append(data, func() []byte {
		x := make([]byte, 0)
		for _, signal := range asdu.ios {
			x = append(x, signal.Data()...)
		}
		return x
	}()...)
	return data
}

/*
TypeID (Type Identification, 1 byte):
- value range:
  - 0 is not used;
  - 1-127 is used for standard IEC 101 definitions, there are presently 58 specific types defined:
    | Type ID | Group                                    |
    | 1-40    | Process information in monitor direction |
    | 45-51   | Process information in control direction |
    | 70      | System information in monitor direction  |
    | 100-106 | System information in control direction  |
    | 110-113 | Parameter in control direction           |
    | 120-126 | File transfer                            |
  - 128-135 is reserved for message routing;
  - 136-255 for special use.
*/
type TypeID uint8

const (
	// Process information in monitor direction

	// MSpNa1 indicates single point information.
	// InformationElement Format: SIQ
	// Valid COT: 2,3,5,11,20,20+G
	// [遥信 - 单点 - 不带时标]
	MSpNa1 TypeID = 0x1
	// MSpTa1 indicates single point information with time tag CP24Time2a.
	// InformationElement Format: SIQ + CP24Time2a
	// Valid COT: 3,5,11,12
	// [遥信 - 单点 - 3 字节时标]
	MSpTa1 TypeID = 0x2
	// MDpNa1 indicates double point information.
	// InformationElement Format: DIQ
	// Valid COT: 2,3,5,11,12,20,20+G
	// [遥信 - 双点 - 不带时标]
	MDpNa1 TypeID = 0x3
	// MDpTa1 indicates double point information with time tag CP24Time2a.
	// InformationElement Format: DIQ + CP24Time2a
	// Valid COT: 3,5,11,12
	// [遥信 - 双点 - 3 字节时标]
	MDpTa1 TypeID = 0x4
	// MMeNd1 indicates measured value, normalized value without quality descriptor
	// InformationElement Format: NVA
	// Valid COT: 1,2,3,5,11,12,20,20+G
	// [遥测 - 归一化值 - 不带时标 - 不带品质描述]
	MMeNd1 TypeID = 0x15 // 21

	// Process telegrams with long time tag (7 bytes)

	// MSpTb1 indicates single point information with time tag CP56Time2a.
	// InformationElement Format: SIQ + CP56Time2a
	// Valid COT: 3,5,11,12
	MSpTb1 TypeID = 0x1e
	// MDpTb1 indicates double point information with time tag CP56Time2a.
	// InformationElement Format: DIQ + CP56Time2a
	// Valid COTs: 3,5,11,12
	MDpTb1 TypeID = 0x1f

	// System information in control direction.

	// CIcNa1 indicates general interrogation command. [召唤全数据]
	// InformationElement Format: QOI
	// Valid COT: 6,7,8,9,10,44,45,46,47
	// ASDU Body: 1 InformationObject [ 3 bytes IOA + 1 byte Value ]
	CIcNa1 TypeID = 0x64 // 100
	// CCiNa1 indicates counter interrogation command. [召唤全电度]
	// InformationElement Format: QCC
	// Valid COT: 6,7,8,9,10,44,45,46,47
	CCiNa1 TypeID = 0x65 // 101
	// CCsNa1 indicates clock synchronization command. [时钟同步]
	// InformationElement Format: CP56Time2a
	// Valid COT: 3,6,7,44,45,46,47
	CCsNa1 TypeID = 0x67 // 103
)

func (asdu *ASDU) parseTypeID(data byte) TypeID {
	asdu.typeID = TypeID(data)
	return asdu.typeID
}

/*
SQ (Structure Qualifier, 1 bit) specifies how information objects or elements are addressed.
- SQ=0 (false): each ASDU contains one or more than one equal information objects:
  | <-              8 bits              -> |
  | Type Identification              [1B]  | --------------------
  | 0 | Number of objects            [7b]  |           |
  | T | P/N | Cause of transmission  [6b]  | Data Unit Identifier
  | Original address (ORG)           [1B]  |           |
  | ASDU address fields              [2B]  | --------------------
  | Information object address (IOA) [3B]  | --------------------
  | Information Elements                   | Information Object 1
  | Time Tag (if used)                     | --------------------
  | Information object address (IOA) [3B]  | --------------------
  | Information Elements                   | Information Object 2
  | Time Tag (if used)                     | --------------------
  | Information object address (IOA) [3B]  | --------------------
  | Information Elements                   | Information Object N
  | Time Tag (if used)                     | --------------------
  | <-              SQ = 0              -> |
  - the number of objects is binary coded (NumberOfObjects), and defines the number of the information objects;
  - each information object has its own information object address (IOA);
  - each single element or a combination of elements of object is addressed by the IOA.
  - [personal guess] SQ=0 is used to transmit a set of discontinuous values.
- SQ=1  (true): each ASDU contains just one information object.
  | <-              8 bits              -> |
  | Type Identification              [1B]  | --------------------
  | 1 | Number of objects            [7b]  |           |
  | T | P/N | Cause of transmission  [6b]  | Data Unit Identifier
  | Original address (ORG)           [1B]  |           |
  | ASDU address fields              [2B]  | --------------------
  | Information object address (IOA) [3B]  | --------------------
  | Information Element 1                  |           |
  | Information Element 2                  |           |
  | Information Element 3                  | Information Object
  | Information Element N                  |           |
  | Time Tag (if used)                     | --------------------
  | <-              SQ = 1              -> |
  - the number of elements is binary coded (NumberOfObjects), and defines the number of the information elements;
  - there is just one information object address, which is the address of the first information element, the following
    information elements are identified by numbers continuous by +1 from this offset;
  - all information elements are of the same format, such as a measured value.
  - [personal guess] SQ=1 is used to transmit a sequence of continuous values to save bandwidth.
*/
type SQ bool

func (asdu *ASDU) parseSQ(data byte) SQ {
	asdu.sq = (data & (1 << 7)) == 1<<7
	return asdu.sq
}

/*
NOO (Number of Objects/Elements, 7 bits).
*/
type NOO = uint8

func (asdu *ASDU) parseNOO(data byte) NOO {
	asdu.nObjs = data & 0b1111111
	return asdu.nObjs
}

/*
T (Test, 1 bit) defines ASDUs which generated during test conditions. That is to say, it is not intended to control the
process or change the system state.
- T=0 (false): no test, used in the product environment.
- T=1  (true): test, used in the development environment.
*/
type T bool // Test

func (asdu *ASDU) parseT(data byte) T {
	asdu.t = (data & (1 << 7)) == 1<<7
	return asdu.t
}

/*
PN (Positive/Negative, 1 bit) indicates the positive or negative confirmation of an activation requested by a primary
application function. The bit is used when the control command is mirrored in the monitor direction, and it provides
indication of whether the command was executed or not.
- PN=0 (false): positive confirm.
- PN=1  (true): negative confirm.
*/
type PN bool

func (asdu *ASDU) parsePN(data byte) PN {
	asdu.pn = (data & (1 << 6)) == 1<<6
	return asdu.pn
}

/*
COT (Cause of Transmission, 6 bits) is used to control message routing.
- value range:
  - 0 is not defined!
  - 1-47 is used for standard IEC 101 definitions
  - 48-63 is for special use (private range)

    - COT field is used to control the routing of messages both on the communication network, and within a station,
      directing by ASDU to the correct program or task for processing. ASDUs in control direction are confirmed application
      services and may be mirrored in monitor direction with different causes of transmission.
    - COT is a 6-bit code which is used in interpreting the information at the destination station. Each defined ASDU
      type has a defined subset of the codes which are meaningful with it.
*/
type COT uint8

const (
	// the standard definitions of COT
	// 14-19 is reserved for further compatible definitions
	CotPer, CotCyc COT = 1, 1 // periodic, cyclic
	CotBack        COT = 2    // background scan
	CotSpt         COT = 3    // spontaneous
	CotInit        COT = 4    // initialized
	CotReq         COT = 5    // request or requested
	CotAct         COT = 6    // activation
	CotActCon      COT = 7    // activation confirmation
	CotDeact       COT = 8    // deactivation
	CotDeactCon    COT = 9    // deactivation confirmation
	CotActTerm     COT = 10   // activation termination
	CotRetRem      COT = 11   // return information caused by a remote command
	CotRetLoc      COT = 12   // return information caused by a local command
	CotFile        COT = 13   // file transfer
	CotInrogen     COT = 20   // interrogated by general interrogation
	CotInro1       COT = 21   // interrogated by interrogation group1
	CotInro2       COT = 22   // interrogated by interrogation group2
	CotInro3       COT = 23   // interrogated by interrogation group3
	CotInro4       COT = 24   // interrogated by interrogation group4
	CotInro5       COT = 25   // interrogated by interrogation group5
	CotInro6       COT = 26   // interrogated by interrogation group6
	CotInro7       COT = 27   // interrogated by interrogation group7
	CotInro8       COT = 28   // interrogated by interrogation group8
	CotInro9       COT = 29   // interrogated by interrogation group9
	CotInro10      COT = 30   // interrogated by interrogation group10
	CotInro11      COT = 31   // interrogated by interrogation group11
	CotInro12      COT = 32   // interrogated by interrogation group12
	CotInro13      COT = 33   // interrogated by interrogation group13
	CotInro14      COT = 34   // interrogated by interrogation group14
	CotInro15      COT = 35   // interrogated by interrogation group15
	CotInro16      COT = 36   // interrogated by interrogation group16
	CotReqcogen    COT = 37   // interrogated by counter general interrogation
	CotReqco1      COT = 38   // interrogated by interrogation counter group 1
	CotReqco2      COT = 39   // interrogated by interrogation counter group 2
	CotReqco3      COT = 40   // interrogated by interrogation counter group 3
	CotReqco4      COT = 41   // interrogated by interrogation counter group 4
	CotUnType      COT = 44   // unknown type
	CotUnCause     COT = 45   // unknown cause
	CotUnAsduAddr  COT = 46   // unknown asdu address
	CotUnObjAddr   COT = 47   // unknown object address

	// TODO How to support COT for special use?
)

func (asdu *ASDU) parseCOT(data byte) COT {
	asdu.cot = COT(data & 0b111111)
	return asdu.cot
}

/*
ORG (Originator Address, 1 byte) provides a method for a controlling station to explicitly identify itself.
- The originator address is optional when there is only one controlling station in a system. If it is not used, all bits
  are set to zero.
- It is required when where is more than one controlling station, or some stations are dual-mode. In this case,
  the address can be used to direct command confirmations back to the particular controlling station rather than to the
  whole system.
- If there is more than one single source in a system defined, the ASDUs in monitor direction have to be directed to
  all relevant sources of the system. In this case the specific affected source has to select its specific ASDUs.

TODO What's the differences between ORG and TCP endpoint (IP + PORT)? Can we identify the source by TCP endpoint?
*/
type ORG uint8

func (asdu *ASDU) parseORG(data byte) ORG {
	asdu.org = ORG(data)
	return asdu.org
}

/*
COA (Common Address of ASDU, 2 bytes) is normally interpreted as a station address.
- COA is either 1 or 2 bytes in length, fixed on pre-system basis. The value range of 2 bytes (the standard):
  - 0 is not used;
  - 1-65534 means a station address;
  - 65535 means global address, and it is broadcast in control direction have to be answered in monitor direction by
    the address that is the specific defined common address (station address).
- Global Address is used when the same application function must be initiated simultaneously. It's restricted to the
  following ASDUs:
  - TypeID = CIcNa1: replay with particular system data snapshot at common time
  - TypeID = CCiNa1: freeze totals at common time
  - TypeID = CCsNa1: synchronize clocks to common time
  - TypeID = C_RP_NC_1: simultaneous reset
*/
type COA = uint16

func (asdu *ASDU) parseCOA(data []byte) COA {
	asdu.coa = binary.LittleEndian.Uint16([]byte{data[0], data[1]})
	return asdu.coa
}
