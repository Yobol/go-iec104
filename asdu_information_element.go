package iec104

/*
InformationElement is a building block used to transmit information. Format and length of each information differs
and is given by the standard. The standard also describes how encoded values are interpreted.
*/
type InformationElement struct {
	TypeID  TypeID            `json:"type_id"`
	Address IOA               `json:"address"`
	Value   float64           `json:"value"`
	Raw     []byte            `json:"raw"`
	Quality QualityDescriptor `json:"quality"`
	Ts      uint64            `json:"ts"`

	Format InformationElementFormat
}

func (asdu *ASDU) parseInformationElement(data []byte, ie *InformationElement) {
	switch asdu.typeID {
	case MSpNa1:
		switch asdu.cot {
		case CotInrogen:
			ie.Format = []InformationElementType{SIQ}
			ie.Quality = ParseQualityDescriptor(data[0])
			ie.Value = float64(parseLittleEndianUint16([]byte{data[0] & 0b1, 0x00})) // 0b1 represents open; 0b0 represents close.
			_lg.Debugf("receive i frame: single point information response of general interrogation at %d is %f "+
				"with Quality[IV: %v, NT: %v, SB: %v, BL: %v] [总召唤响应 - 带品质描述/不带时标单点遥信]", ie.Address,
				ie.Value, (ie.Quality&IV) == IV, (ie.Quality&NT) == NT, (ie.Quality&SB) == SB, (ie.Quality&BL) == BL)
		}
	case MDpNa1:
		switch asdu.cot {
		case CotInrogen:
			ie.Format = []InformationElementType{DIQ}
			ie.Quality = ParseQualityDescriptor(data[0])
			ie.Value = float64(parseLittleEndianUint16([]byte{data[0] & 0b11, 0x00})) // 0b1 represents close; 0b11 represents open.
			_lg.Debugf("receive i frame: double point information response of general interrogation at %d is %f "+
				"with Quality[IV: %v, NT: %v, SB: %v, BL: %v] [总召唤响应 - 带品质描述/不带时标双点遥信]", ie.Address,
				ie.Value, (ie.Quality&IV) == IV, (ie.Quality&NT) == NT, (ie.Quality&SB) == SB, (ie.Quality&BL) == BL)
		}
	case MMeNd1:
		switch asdu.cot {
		case CotInrogen:
			ie.Format = []InformationElementType{NVA}
			ie.Value = float64(parseLittleEndianInt16(data[:2]))
			_lg.Debugf("receive i frame: double point information response of general interrogation at %d is %f "+
				"[总召唤响应 - 不带品质描述/不带时标/归一化遥测]", ie.Address, ie.Value)
		}
	case CIcNa1:
		switch asdu.cot {
		case CotActCon:
			_lg.Debugf("receive i frame: confirmation of general interrogation [总召唤确认]")
		case CotActTerm:
			_lg.Debugf("receive i frame: termination of general interrogation [总召唤结束]")
		}
	default:
		panic(any("implement me"))
	}
}

type InformationElementFormat []InformationElementType

type InformationElementType int

const (
	// Process information in monitor direction.

	// SIQ indicates single-point information with quality descriptor. [单点遥信]
	// Length: 1 byte
	// TypeID: MSpNa1, 2 ,30
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   | IV  | NT  | SB  | BL |  0  |  0  |  0  | SPI |
	// https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1587
	// SIQ contains a set quality bits.
	SIQ InformationElementType = iota
	// DIQ indicates double-point information with quality descriptor.
	// Length: 1 byte
	// TypeID: MDpNa1
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   | IV  | NT  | SB  | BL |  0  |  0  |    DPI    |
	// https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1607
	// DIQ contains a set quality bits.
	DIQ
	// BSI indicates binary state information.
	// Length: 4 bytes
	// TypeID: 7,8,33,51
	BSI
	// SCD indicates status and change detection.
	// Length: 4 bytes
	// TypeID: 20
	SCD
	// QDS indicates quality descriptor.
	// Length: 4 bytes
	// TypeID: 5,6,7,8,9,10,11,12,13,14,20,32,33,34,36
	QDS
	// VTI indicates value with transient state indication.
	// Length: 1 byte
	// TypeID: 5,6,32
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   |  T  |                Value I7                |
	// VTI contains a 7-bit value in the range [-64, 63].
	VTI
	// NVA indicates normalized value.
	// Length: 2 bytes
	// TypeID: 9,10, MMeNd1,34,48,110
	NVA
	// SVA indicates scaled value.
	// Length: 2 bytes
	// TypeID: 11,12,49,111
	SVA
	// IEEESTD754 indicates short floating point number.
	// Length: 4 bytes
	// TypeID: 13,14,36,50,112
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   |                  Value I16                   |
	// SVA contains a 16-bit value in the range [-32768, 32767] which represents a fixed decimal point number. However,
	// the position of the decimal point is not transmitted by the value, but it is set in the system database.
	// For example, a value of 39.5 amps may be transmitted as 395 where the resolution is fixed at 0.1 amp.
	IEEESTD754
	// BCR indicates binary counter reading
	// Length: 5 bytes
	// TypeID: 15,16,37
	BCR

	// Protection.

	// SEP indicates single event of protection equipment.
	// Length: 1 byte
	// TypeID: 17,38
	SEP
	// SPE indicates start events of protection equipment.
	// Length: 1 byte
	// TypeID: 18,39
	SPE
	// OCI indicates output circuit information of protection equipment.
	// Length: 1 byte
	// TypeID: 19,40
	OCI
	// QDP indicates quality descriptor for events of protection equipment.
	// Length: 1 byte
	// TypeID: 18,19,39,40
	QDP

	// Commands.

	// SCO indicates single command.
	// Length: 1 byte
	// TypeID: 45
	SCO
	// DCO indicates double command.
	// Length: 1 byte
	// TypeID: 46
	DCO
	// RCO indicates regulating step command.
	// Length: 1 byte
	// TypeID: 47
	RCO

	// Time.

	// CP56Time2a indicates 7-byte binary time.
	// Length: 7 bytes
	// TypeID: 4,6,8,10,12,14,16,17,18,19,31,32,33,34,36,37,38,39,40,103,126
	CP56Time2a
	// CP24Time2a indicates 3-byte binary time.
	// Length: 3 bytes
	// TypeID: 4,5,6,8,10,12,14,16,17,18,19,31,32,33,34,36,37,38,39,40
	CP24Time2a
	// CP16Time2a indicates 2-byte binary time/
	// Length: 2 bytes
	// TypeID: 17,18,19,38,39,40,106
	CP16Time2a

	// Qualifiers

	// QOI indicates qualifier of interrogation.
	// Length: 1 byte
	// TypeID: CIcNa1
	QOI
	// QCC indicates qualifier of counter interrogation command.
	// Length: 1 byte
	// TypeID: 101
	QCC
	// QPM indicates qualifier of parameter of measured values.
	// Length: 1 byte
	// TypeID: 110,112
	QPM
	// QPA indicates qualifier of parameter activation.
	// Length: 1 byte
	// TypeID: 111,113
	QPA
	// QRP indicates qualifier of reset process command.
	// Length: 1 byte
	// TypeID: 105
	QRP
	// QOC indicates qualifier of command.
	// Length: 1 byte
	// TypeID: 45,46,47,48,49,50
	QOC
	// QOS indicates qualifier of set-point command.
	// Length: 1 byte
	// TypeID: 48,49,50
	QOS

	// File Transfer.

	// FRQ indicates file ready qualifier.
	// Length: 1 byte
	// TypeID: 120
	FRQ
	// SRQ indicates section ready qualifier.
	// Length: 1 byte
	// TypeID: 121
	SRQ
	// SCQ indicates select and call qualifier.
	// Length: 1 byte
	// TypeID: 122
	SCQ
	// LSQ indicates last section or segment qualifier.
	// Length: 1 byte
	// TypeID: 123
	LSQ
	// AFQ indicates acknowledge file or section qualifier.
	// Length: 1 byte
	// TypeID: 124
	AFQ
	// NOF indicates name of file.
	// Length: 2 bytes
	// TypeID: 120,121,122,123,124,125,126
	NOF
	// NOS indicates name of section.
	// Length: 2 bytes
	// TypeID: 121,122,123,124,125
	NOS
	// LOF indicates length of file or section.
	// Length: 3 bytes
	// TypeID: 120,121
	LOF
	// LOS indicates length of segment.
	// Length: 1 byte
	// TypeID: 125
	LOS
	// CHS indicates checksum.
	// Length: 1 byte
	// TypeID: 123
	CHS
	// SOF indicates status of file.
	// Length: 1 byte
	// TypeID: 126
	SOF

	// Miscellaneous.

	// COI indicates cause of initialization.
	// Length: 1 byte
	// TypeID: 70
	COI
	// FBP indicates fixed test bit pattern.
	// Length: 2 bytes
	// TypeID: 104
	FBP
)

type QualityDescriptor byte

const (
	IV QualityDescriptor = 1 << 7 // invalid -> bad quality
	NT QualityDescriptor = 1 << 6
	SB QualityDescriptor = 1 << 5
	BL QualityDescriptor = 1 << 4
)

func ParseQualityDescriptor(x byte) QualityDescriptor {
	return QualityDescriptor(x & 0xf0)
}
