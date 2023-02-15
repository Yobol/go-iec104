package iec104

import (
	"math"
	"time"
)

/*
InformationElement is a building block used to transmit information. Format and length of each information differs
and is given by the standard. The standard also describes how encoded values are interpreted.
*/
type InformationElement struct {
	TypeID  TypeID            `json:"type_id"`
	Address IOA               `json:"address"`
	Value   float64           `json:"value"`
	Raw     []byte            `json:"raw"`
	Quality QualityDescriptor `json:"quality"` // if the value's quality is not zero, it means the value is not valid!
	Ts      time.Time         `json:"ts"`

	Format InformationElementFormat

	data   []byte
	offset int
}

func (ie *InformationElement) IsValid() bool {
	return ie.Quality == 0
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1278
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2413
func (ie *InformationElement) getSIQ() {
	ie.Format = append(ie.Format, SIQ)
	ie.Quality = QualityDescriptor(ie.data[ie.offset] & 0xf0)
	ie.Value = float64(parseLittleEndianUint16([]byte{ie.data[ie.offset] & 0b1, 0x00})) // 0b1 represents open; 0b0 represents close.

	ie.offset++
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1298
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2437
func (ie *InformationElement) getDIQ() {
	ie.Format = append(ie.Format, DIQ)
	ie.Quality = QualityDescriptor(ie.data[ie.offset] & 0xf0)
	ie.Value = float64(parseLittleEndianUint16([]byte{ie.data[ie.offset] & 0b11, 0x00})) // 0b01 represents close; 0b10 represents open.

	ie.offset++
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1367
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2637
func (ie *InformationElement) getNVA() {
	ie.Format = append(ie.Format, NVA)
	ie.Value = float64(parseLittleEndianInt16(ie.data[ie.offset:ie.offset+2])) / 32768

	ie.offset += 2
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1398
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2641
func (ie *InformationElement) getSVA() {
	ie.Format = append(ie.Format, SVA)
	ie.Value = float64(parseLittleEndianInt16(ie.data[ie.offset : ie.offset+2]))

	ie.offset += 2
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1417
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2633
func (ie *InformationElement) getIEEESTD754() {
	ie.Format = append(ie.Format, IEEE754STD)
	ie.Value = float64(math.Float32frombits(parseLittleEndianUint32(ie.data[ie.offset : ie.offset+4])))
	ie.offset += 4
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1479
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2497
func (ie *InformationElement) getQOS() {
	ie.Format = append(ie.Format, QOS)

	ie.offset += 1
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1496
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2509
func (ie *InformationElement) getSCO() {
	ie.Format = append(ie.Format, SCO)
	ie.Value = float64(parseLittleEndianUint16([]byte{ie.data[ie.offset], 0x00}))

	ie.offset += 1
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1514
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2525
func (ie *InformationElement) getDCO() {
	ie.Format = append(ie.Format, DCO)
	ie.Value = float64(parseLittleEndianUint16([]byte{ie.data[ie.offset], 0x00}))

	ie.offset += 1
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1532
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2541
func (ie *InformationElement) getRCO() {
	ie.Format = append(ie.Format, RCO)
	ie.Value = float64(parseLittleEndianUint16([]byte{ie.data[ie.offset], 0x00}))

	ie.offset += 1
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1318
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2461
func (ie *InformationElement) getQDS() {
	ie.Format = append(ie.Format, QDS)
	ie.Quality = QualityDescriptor(ie.data[ie.offset] & 0xff)

	ie.offset++
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1453
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2605
func (ie *InformationElement) getBCR() {
	ie.Format = append(ie.Format, BCR)
	ie.Value = float64(parseLittleEndianUint32(ie.data[ie.offset : ie.offset+4])) // data[4] is the description information.

	ie.offset += 5
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1084
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2353
func (ie *InformationElement) getCP24Time2a() {
	millisecond := parseLittleEndianUint16(ie.data[ie.offset : ie.offset+2])
	nanosecond := (int(millisecond) % 1000) * int(time.Millisecond)
	second := int(millisecond / 1000)
	minute := int(ie.data[ie.offset+2] & 0x3f)

	// FIXME How to set year, month, day and hour for CP24Time2a?
	ie.Ts = time.Date(0, time.January, 1, 0, minute, second, nanosecond, time.Local)
	ie.offset += 3
}

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1161
func (ie *InformationElement) getCP56Time2a() {
	millisecond := parseLittleEndianUint16(ie.data[ie.offset : ie.offset+2])
	nanosecond := (int(millisecond) % 1000) * int(time.Millisecond)
	second := int(millisecond / 1000)
	minute := int(ie.data[ie.offset+2] & 0x3f)
	hour := int(ie.data[ie.offset+3] & 0x1f)
	day := int(ie.data[ie.offset+4] & 0x1f)
	month := int(ie.data[ie.offset+5] & 0x0f)
	year := int(ie.data[ie.offset+6]&0x7f) + 2000
	if year < 70 {
		year += 100
	}

	ie.Ts = time.Date(year, time.Month(month), day, hour, minute, second, nanosecond, time.Local)
	ie.offset += 7
}

func (asdu *ASDU) parseInformationElement(data []byte, ie *InformationElement) {
	ie.data = data

	switch asdu.typeID {
	case MSpNa1:
		ie.getSIQ()
		switch asdu.cot {
		case CotPerCyc:
			_lg.Debugf("receive i frame: single point information of periodically/cyclically syncing at %d is %f "+
				"with Quality[IV: %v, NT: %v, SB: %v, BL: %v] [全遥信 - 带品质描述/不带时标单点遥信]", ie.Address,
				ie.Value, (ie.Quality&IV) == IV, (ie.Quality&NT) == NT, (ie.Quality&SB) == SB, (ie.Quality&BL) == BL)
			asdu.sendSFrame = true
		case CotSpont:
			_lg.Debugf("receive i frame: single point information of spontenuous change at %d is %f "+
				"with Quality[IV: %v, NT: %v, SB: %v, BL: %v] [变化遥信 - 带品质描述/不带时标单点遥信]", ie.Address,
				ie.Value, (ie.Quality&IV) == IV, (ie.Quality&NT) == NT, (ie.Quality&SB) == SB, (ie.Quality&BL) == BL)
			asdu.sendSFrame = true
		case CotInrogen:
			_lg.Debugf("receive i frame: single point information response of general interrogation at %d is %f "+
				"with Quality[IV: %v, NT: %v, SB: %v, BL: %v] [总召唤响应 - 带品质描述/不带时标单点遥信]", ie.Address,
				ie.Value, (ie.Quality&IV) == IV, (ie.Quality&NT) == NT, (ie.Quality&SB) == SB, (ie.Quality&BL) == BL)
		}
		asdu.toBeHandled = true
	case MSpTa1:
		ie.getSIQ()
		ie.getCP24Time2a()
		switch asdu.cot {
		case CotSpont:
			_lg.Debugf("receive i frame: single point information of spontenuous change with 24-bit time tag "+
				"at %d is %f [%s] [自发突变 - 带 24 位时标的单点遥信]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MDpNa1:
		ie.getDIQ()
		switch asdu.cot {
		case CotPerCyc:
			_lg.Debugf("receive i frame: double point information of periodically/cyclically syncing at %d is %f "+
				"with Quality[IV: %v, NT: %v, SB: %v, BL: %v] [全遥信 - 带品质描述/不带时标双点遥信]", ie.Address,
				ie.Value, (ie.Quality&IV) == IV, (ie.Quality&NT) == NT, (ie.Quality&SB) == SB, (ie.Quality&BL) == BL)
			asdu.sendSFrame = true
		case CotSpont:
			_lg.Debugf("receive i frame: double point information of spontenuous change at %d is %f "+
				"with Quality[IV: %v, NT: %v, SB: %v, BL: %v] [变化遥信 - 带品质描述/不带时标双点遥信]", ie.Address,
				ie.Value, (ie.Quality&IV) == IV, (ie.Quality&NT) == NT, (ie.Quality&SB) == SB, (ie.Quality&BL) == BL)
			asdu.sendSFrame = true
		case CotInrogen:
			_lg.Debugf("receive i frame: double point information response of general interrogation at %d is %f "+
				"with Quality[IV: %v, NT: %v, SB: %v, BL: %v] [总召唤响应 - 带品质描述/不带时标双点遥信]", ie.Address,
				ie.Value, (ie.Quality&IV) == IV, (ie.Quality&NT) == NT, (ie.Quality&SB) == SB, (ie.Quality&BL) == BL)
		}
		asdu.toBeHandled = true
	case MDpTa1:
		ie.getDIQ()
		ie.getCP24Time2a()
		switch asdu.cot {
		case CotSpont:
			_lg.Debugf("receive i frame: double point information of spontenuous change with 24-bit time tag "+
				"at %d is %f [%s] [自发突变 - 带 24 位时标的双点遥信]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeNa1:
		ie.getNVA()
		ie.getQDS()
		switch asdu.cot {
		default:
			_lg.Debugf("receive i frame: normalized value with quality descriptor without time tag "+
				"at %d is %f [不带时标归一化值遥测]", ie.Address, ie.Value)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeTa1:
		ie.getNVA()
		ie.getQDS()
		ie.getCP24Time2a()
		switch asdu.cot {
		default:
			_lg.Debugf("receive i frame: normalized value with quality descriptor with time tag CP24Time2a "+
				"at %d is %f [%s] [带 24 位时归一化值遥测]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeNb1:
		ie.getSVA()
		ie.getQDS()
		switch asdu.cot {
		default:
			_lg.Debugf("receive i frame: scaled value with quality descriptor without time tag "+
				"at %d is %f [不带时标标度化值遥测]", ie.Address, ie.Value)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeTb1:
		ie.getSVA()
		ie.getQDS()
		ie.getCP24Time2a()
		switch asdu.cot {
		default:
			_lg.Debugf("receive i frame: scaled value with quality descriptor with time tag CP24Time2a "+
				"at %d is %f [%s] [带 24 位时标标度化值遥测]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeNc1:
		ie.getIEEESTD754()
		ie.getQDS()
		switch asdu.cot {
		default:
			_lg.Debugf("receive i frame: short floating point value with quality descriptor without time tag "+
				"at %d is %f [不带时标单精度浮点数值遥测]", ie.Address, ie.Value)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeTc1:
		ie.getIEEESTD754()
		ie.getQDS()
		ie.getIEEESTD754()
		switch asdu.cot {
		default:
			_lg.Debugf("receive i frame: short floating point value with quality descriptor without time tag "+
				"at %d is %f [%s] [带 24 位时标单精度浮点数值遥测]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeNd1:
		ie.getNVA()
		switch asdu.cot {
		case CotPerCyc:
			_lg.Debugf("receive i frame: measured value, normalized value without quality descriptor at %d is %f "+
				"[全遥测 - 不带品质描述/不带时标/归一化遥测]", ie.Address, ie.Value)
			asdu.sendSFrame = true
		case CotSpont:
			_lg.Debugf("receive i frame: measured value, normalized value without quality descriptor at %d is %f "+
				"[自发突变 - 不带品质描述/不带时标/归一化遥测]", ie.Address, ie.Value)
			asdu.sendSFrame = true
		case CotInrogen:
			_lg.Debugf("receive i frame: measured value, normalized value without quality descriptor at %d is %f "+
				"[总召唤响应 - 不带品质描述/不带时标/归一化遥测]", ie.Address, ie.Value)
		}
		asdu.toBeHandled = true
	case MItNa1:
		ie.getBCR()
		switch asdu.cot {
		case CotReqcogen:
			_lg.Debugf("receive i frame: response of counter interrogation at %d is %f "+
				"[总电度响应]", ie.Address, ie.Value)
			asdu.toBeHandled = true
		}
	case MItTa1:
		ie.getBCR()
		ie.getCP24Time2a()
		switch asdu.cot {
		case CotReqcogen:
			_lg.Debugf("receive i frame: response of counter interrogation at %d is %f [%s]"+
				"[总电度响应]", ie.Address, ie.Value, ie.Ts)
			asdu.toBeHandled = true
		}
	case MSpTb1:
		ie.getSIQ()
		ie.getCP56Time2a()
		switch asdu.cot {
		case CotSpont:
			_lg.Debugf("receive i frame: single point information of spontenuous change with 56-bit time tag "+
				"at %d is %f [%s] [自发突变 - 带 56 位时标的单点遥信]", ie.Address, ie.Value, ie.Ts)
			asdu.toBeHandled = true
		}
		asdu.sendSFrame = true
	case MDpTb1:
		ie.getDIQ()
		ie.getCP56Time2a()
		switch asdu.cot {
		case CotSpont:
			_lg.Debugf("receive i frame: double point information of spontenuous change with 56-bit time tag "+
				"at %d is %f [%s] [自发突变 - 带 56 位时标的双点遥信]", ie.Address, ie.Value, ie.Ts)
		case CotReq:
			_lg.Debugf("receive i frame: double point information of request with 56-bit time tag "+
				"at %d is %f [%s] [请求 - 带 56 位时标的双点遥信]", ie.Address, ie.Value, ie.Ts)
		default:
			_lg.Debugf("receive i frame: double point information with 56-bit time tag "+
				"at %d is %f [%s] [带 56 位时标的双点遥信]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeTd1:
		ie.getNVA()
		ie.getQDS()
		ie.getCP56Time2a()
		switch asdu.cot {
		case CotSpont:
			_lg.Debugf("receive i frame: normalized value of spontenuous change with 56-bit time tag "+
				"at %d is %f [%s] [自发突变 - 带 56 位时标的归一化值遥测]", ie.Address, ie.Value, ie.Ts)
		case CotReq:
			_lg.Debugf("receive i frame: normalized value of request with 56-bit time tag "+
				"at %d is %f [%s] [请求 - 带 56 位时标的归一化值遥测]", ie.Address, ie.Value, ie.Ts)
		default:
			_lg.Debugf("receive i frame: normalized value with 56-bit time tag "+
				"at %d is %f [%s] [带 56 位时标的归一化值遥测]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeTe1:
		ie.getSVA()
		ie.getQDS()
		ie.getCP56Time2a()
		switch asdu.cot {
		case CotSpont:
			_lg.Debugf("receive i frame: scaled value of spontenuous change with 56-bit time tag "+
				"at %d is %f [%s] [自发突变 - 带 56 位时标的标度化值遥测]", ie.Address, ie.Value, ie.Ts)
		case CotReq:
			_lg.Debugf("receive i frame: scaled value of request with 56-bit time tag "+
				"at %d is %f [%s] [请求 - 带 56 位时标的标度化值遥测]", ie.Address, ie.Value, ie.Ts)
		default:
			_lg.Debugf("receive i frame: scaled value with 56-bit time tag "+
				"at %d is %f [%s] [带 56 位时标的标度化值遥测]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MMeTf1:
		ie.getIEEESTD754()
		ie.getQDS()
		ie.getCP56Time2a()
		switch asdu.cot {
		case CotSpont:
			_lg.Debugf("receive i frame: short floating point value of spontenuous change with 56-bit time tag "+
				"at %d is %f [%s] [自发突变 - 带 56 位时标的单精度值遥测]", ie.Address, ie.Value, ie.Ts)
		case CotReq:
			_lg.Debugf("receive i frame: short floating point value of request with 56-bit time tag "+
				"at %d is %f [%s] [请求 - 带 56 位时标的单精度值遥测]", ie.Address, ie.Value, ie.Ts)
		default:
			_lg.Debugf("receive i frame: short floating point value with 56-bit time tag "+
				"at %d is %f [%s] [带 56 位时标的单精度值遥测]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case MItTb1:
		ie.getBCR()
		ie.getCP56Time2a()
		switch asdu.cot {
		case CotSpont:
			_lg.Debugf("receive i frame: integrated totals of spontenuous change with 56-bit time tag "+
				"at %d is %f [%s] [自发突变 - 带 56 位时标的电度]", ie.Address, ie.Value, ie.Ts)
		case CotReqcogen:
			_lg.Debugf("receive i frame: integrated totals of counter interrogation with 56-bit time tag "+
				"at %d is %f [%s] [电度召唤 - 带 56 位时标的电度]", ie.Address, ie.Value, ie.Ts)
		default:
			_lg.Debugf("receive i frame: short floating point value with 56-bit time tag "+
				"at %d is %f [%s] [带 56 位时标的电度]", ie.Address, ie.Value, ie.Ts)
		}
		asdu.toBeHandled = true
		asdu.sendSFrame = true
	case CScNa1:
		ie.getSCO()
		switch asdu.cot {
		case CotActCon:
			if ie.Value == 0x80 {
				_lg.Debugf("receive i frame: select confirmation of single command - open [单点命令遥控选择确认 - 分闸]")
				asdu.cmdRsp = &cmdRsp{}
			} else if ie.Value == 0x81 {
				_lg.Debugf("receive i frame: select confirmation of single command - close [单点命令遥控选择确认 - 合闸]")
				asdu.cmdRsp = &cmdRsp{}
			} else if ie.Value == 0x00 {
				_lg.Debugf("receive i frame: execute confirmation of single command - open [单点命令遥控执行确认 - 分闸]")
				asdu.cmdRsp = &cmdRsp{}
			} else if ie.Value == 0x01 {
				_lg.Debugf("receive i frame: execute confirmation of single command - close [单点命令遥控执行确认 - 合闸]")
				asdu.cmdRsp = &cmdRsp{}
			} else {
				_lg.Debugf("receive i frame: confirmation of single command [单点命令确认]")
			}
		case CotDeactCon:
			if ie.Value == 0x00 {
				_lg.Debugf("receive i frame: undo confirmation of single command - open [单点命令遥控撤销确认 - 分闸]")
			} else if ie.Value == 0x01 {
				_lg.Debugf("receive i frame: undo confirmation of single command - close [单点命令遥控撤销确认 - 合闸]")
			} else {
				_lg.Debugf("receive i frame: confirmation of single command [单点命令激活确认]")
			}
		case CotActTerm:
			_lg.Debugf("receive i frame: termination of single command [单点命令激活终止]")
			asdu.cmdRsp = &cmdRsp{
				err: errSingleCmdTerm{},
			}
		}
	case CDcNa1:
		ie.getDCO()
		switch asdu.cot {
		case CotActCon:
			if ie.Value == 0x81 {
				_lg.Debugf("receive i frame: select confirmation of double command - open [双点命令遥控选择确认 - 分闸]")
				asdu.cmdRsp = &cmdRsp{}
			} else if ie.Value == 0x82 {
				_lg.Debugf("receive i frame: select confirmation of double command - close [双点命令遥控选择确认 - 合闸]")
				asdu.cmdRsp = &cmdRsp{}
			} else if ie.Value == 0x01 {
				_lg.Debugf("receive i frame: execute confirmation of double command - open [双点命令遥控执行确认 - 分闸]")
				asdu.cmdRsp = &cmdRsp{}
			} else if ie.Value == 0x02 {
				_lg.Debugf("receive i frame: execute confirmation of double command - close [双点命令遥控执行确认 - 合闸]")
				asdu.cmdRsp = &cmdRsp{}
			} else {
				_lg.Debugf("receive i frame: confirmation of double command [双点命令激活确认]")
			}
		case CotDeactCon:
			if ie.Value == 0x01 {
				_lg.Debugf("receive i frame: undo confirmation of double command - open [双点命令遥控撤销确认 - 分闸]")
			} else if ie.Value == 0x02 {
				_lg.Debugf("receive i frame: undo confirmation of double command - close [双点命令遥控撤销确认 - 合闸]")
			} else {
				_lg.Debugf("receive i frame: undo confirmation of double command [双点命令遥控取消激活确认]")
			}
		case CotActTerm:
			_lg.Debugf("receive i frame: termination of double command [双点命令激活终止]")
			asdu.cmdRsp = &cmdRsp{
				err: errSingleCmdTerm{},
			}
		}
	case CIcNa1:
		switch asdu.cot {
		case CotActCon:
			_lg.Debugf("receive i frame: confirmation of general interrogation [总召唤确认]")
		case CotActTerm:
			_lg.Debugf("receive i frame: termination of general interrogation [总召唤结束]")
			asdu.sendSFrame = true
		}
	case CCiNa1:
		switch asdu.cot {
		case CotActCon:
			_lg.Debugf("receive i frame: confirmation of counter interrogation [总电度确认]")
		case CotActTerm:
			_lg.Debugf("receive i frame: termination of counter interrogation [总电度结束]")
			asdu.sendSFrame = true
		}
	default:
		_lg.Warnf("unsupported type: TypeID[%X], COT[%X]", asdu.typeID, asdu.cot)
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
	// Length: 1 byte
	// TypeID: 5,6,7,8,9,10,11,12,13,14,20,32,33,34,36
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   | IV  | NT  | SB  | BL |  0  |  0  |  0  | OV  |
	// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L2461
	// QDS contains a set quality bits.
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
	// TypeID: 9,10, MMeNd1, 34,48,110
	// Range: [-1, +1-2^-15]
	// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1367
	NVA
	// SVA indicates scaled value.
	// Length: 2 bytes
	// TypeID: 11,12,49,111
	// Range: [-2^15, +2^15-1]
	// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-iec104.c#L1398
	SVA
	// IEEE754STD indicates short floating point number.
	// Length: 4 bytes
	// TypeID: 13,14,36,50,112
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   |                  Value I16                   |
	// SVA contains a 16-bit value in the range [-32768, 32767] which represents a fixed decimal point number. However,
	// the position of the decimal point is not transmitted by the value, but it is set in the system database.
	// For example, a value of 39.5 amps may be transmitted as 395 where the resolution is fixed at 0.1 amp.
	IEEE754STD
	// BCR indicates binary counter reading.
	// Length: 5 bytes
	// TypeID: MItNa1
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
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   | SE  |              QU            |  0  | ON  |
	//
	// Value Range:
	// - Select  Open  : 0x80;
	// - Select  Close : 0x81;
	// - Execute Open  : 0x00;
	// - Execute Close : 0x01;
	// - Cancel  Open  : 0x00;
	// - Cancel  Close : 0x01;
	//
	// TypeID: CScNa1
	SCO
	// DCO indicates double command.
	// Length: 1 byte
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   | SE  |              QU            |     ON    |
	//
	// Value Range:
	// - Select  Open  : 0x81;
	// - Select  Close : 0x82;
	// - Execute Open  : 0x01;
	// - Execute Close : 0x02;
	// - Cancel  Open  : 0x01;
	// - Cancel  Close : 0x02;
	//
	// TypeID: CDcNa1
	DCO
	// RCO indicates regulating step command.
	// Length: 1 byte
	// Format:
	//   | <-                 8 bits                 -> |
	//   ------------------------------------------------
	//   | SE  |              QU            |     UP    |
	//
	// Value Range:
	// - Select  Open  : 0x81;
	// - Select  Close : 0x82;
	// - Execute Open  : 0x01;
	// - Execute Close : 0x02;
	// - Cancel  Open  : 0x01;
	// - Cancel  Close : 0x02;
	//
	// TypeID: CRcNa1
	RCO

	// Time.

	// CP56Time2a indicates 7-byte binary time.
	// Length: 7 bytes
	// TypeID: MSpTb1, MDpTb1
	CP56Time2a
	// CP24Time2a indicates 3-byte binary time.
	// Length: 3 bytes
	// TypeID:
	CP24Time2a
	// CP16Time2a indicates 2-byte binary time/
	// Length: 2 bytes
	// TypeID:
	CP16Time2a

	// Qualifiers

	// QOI indicates qualifier of general interrogation.
	// Length: 1 byte
	// TypeID: CIcNa1
	QOI
	// QCC indicates qualifier of counter interrogation command.
	// Length: 1 byte
	// TypeID: CCiNa1
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
	// IV = VALID (0) / INVALID (1).
	// - A value is valid if it was correctly acquired. After the acquisition function recognizes abnormal conditions
	//   of the information source (missing or non-operating updating devices) the value is then marked invalid. The
	//   value of the information object is not defined under this condition.
	// - The mark is invalid is used to indicate to the destination that the value may be incorrect due to a fault or
	//   other abnormal condition, and cannot be used.
	IV QualityDescriptor = 1 << 7
	// NT = TOPICAL (0) / NOT TOPICAL (1).
	// - A value is topical if the most recent update was successful. It is not topical if it was not updated
	//   successfully during a specified time interval or if it is unavailable.
	NT QualityDescriptor = 1 << 6
	// SB = NOT SUBSTITUTED (0) / SUBSTITUTED (1).
	// - The value of the information object is provided by the input of an operator (dispatcher) or by an automatic
	//   source.
	// - It means that the value is derived from the normal measurement.
	SB QualityDescriptor = 1 << 5
	// BL = NOT BLOCKED (0) / BLOCKED (1).
	// - The value of information object is blocked for transmission; the value remains in the state that was acquired
	//   before it was blocked. Blocking prevents updating of the value of the point.
	// - Blocking and unblocking may be initiated for example by a local lock or a local automatic cause.
	BL QualityDescriptor = 1 << 4
	// OV = NO OVERFLOW (0) / OVERFLOW (1)
	// - The value of the information object is beyond a predefined range of value (mainly applicable to analog values).
	// - It is used primarily with analog or counter values.
	OV QualityDescriptor = 1 << 0

	// SPI (Single Point Information).
	// - 0 means status OFF;
	// - 1 means status ON.
	SPI QualityDescriptor = 1
	// DPI (Double Point Information).
	// - 0 means intermediate state;
	// - 1 means determined state OFF;
	// - 2 means determined state ON.
	// - 3 means intermediate state;
	DPI QualityDescriptor = 3
)
