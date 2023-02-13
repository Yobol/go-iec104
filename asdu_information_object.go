package iec104

import "encoding/binary"

/*
InformationObject . Each information object is addressed by Information Object
Address (IOA) which identifies the particular data within a defined station. Its length is 3 bytes for IEC 104. The address
is used as destination address in control direction and as source address in monitor direction.
- The third byte of IOA is only used in case of structuring the information object address in order to define unambiguous
  addresses with a specific system.
- If the information object address is not relevant (not used) in some ASDUs, it is set to zero.

All information objects transmitted by one ASDU must have the same ASDU type. If there are more objects of different types
to be transmitted, they are inserted in several ASDUs.

For each defined ASDU type, the IEC 104 standard defines the format of the information object, i.e., what information
elements form such object and how they are structured.
- The following example shows information object Single-point information without time (ASDU type=1). The object format
  has two forms: one for SQ=0 and one for SQ=1. Valid COT for this object are: 2 (background scan), 3 (spontaneous),
  5 (requested), 11, 12 (feedback), 20 +G (interrogated by station interrogation)

        |     Information Object Type 1 (MSpNa1)     |
        | <-                 8 bits                  -> |
        | Information Object Address (IOA)              |
   SQ=0 | IV  | NT  | SB  | BL  |  0  |  0  |  0  | SPI |
  ---------------------------------------------------------
        | <-                 8 bits                  -> |
        | Information Object Address (IOA)              |
   SQ=1 | IV  | NT  | SB  | BL  |  0  |  0  |  0  | SPI |
                                |
                                v
        | IV  | NT  | SB  | BL  |  0  |  0  |  0  | SPI |

- Some information objects contain several information elements. For example, the following example shows information
  object of type 10 (measured value, normalized with time tag). This object is defined only for SQ=0 and contains three
  information elements: normalized value NVA (2 bytes), quality descriptor (1 byte), and binary timestamp (3 bytes).
  For this type of object, valid causes of transmission are 3 (spontaneous), 5 (requested).

        |    Information Object Type 10 (M_ME_TA_1)     |
        | <-                 8 bits                  -> |
        | Information Object Address (IOA)              |
   SQ=0 |                      NVA                      |  normalized value
        |                      NVA                      |
        | IV  | NT  | SB  | BL  |  0  |  0  |  0  | SPI |  quality descriptor
        |                  CP24Time2a                   |  binary timestamp
        |                  CP24Time2a                   |
        |                  CP24Time2a                   |

The number of information objects and information elements within the ASDU is the Number of objects given in the second
byte of ASDU header.
*/
type InformationObject struct {
	ioa IOA
	ies []*InformationElement
}

func (i *InformationObject) Data() []byte {
	data := make([]byte, 0)
	data = append(data, i.serializeIOA()...)
	for _, ie := range i.ies {
		data = append(data, ie.Raw...)
	}
	return data
}

func (i *InformationObject) parseIOA(data []byte) {
	// don't use IOA(binary.LittleEndian.Uint32(append(data, 0x00)))!
	i.ioa = IOA(binary.LittleEndian.Uint32([]byte{data[0], data[1], data[2], 0x00}))
}

func (i *InformationObject) serializeIOA() []byte {
	data := make([]byte, 4, 4)
	binary.LittleEndian.PutUint32(data, uint32(i.ioa))
	return data[:3]
}

func (i *InformationObject) parseCP24Time(data []byte) int32 {
	if len(data) != 3 {
		return 0
	}
	panic(any("implement me"))
	return 0
}

func (i *InformationObject) parseCP56Time(data []byte) int64 {
	if len(data) != 7 {
		return 0
	}
	panic(any("implement me"))
	return 0
}

func (asdu *ASDU) parseInformationObjects(asduBody []byte) {
	ios := make([]*InformationObject, 0)
	signals := make([]*InformationElement, 0)
	defer func() {
		asdu.ios = ios
		asdu.Signals = signals
	}()

	if asdu.sq {
		io := &InformationObject{}
		io.parseIOA(asduBody[:IOALength])

		size := (len(asduBody) - IOALength) / int(asdu.nObjs)
		for i := 0; i < int(asdu.nObjs); i++ {
			ie := &InformationElement{
				TypeID:  asdu.typeID,
				Address: io.ioa + IOA(i),
			}
			asdu.parseInformationElement(asduBody[IOALength+i*size:IOALength+(i+1)*size], ie)
			io.ies = append(io.ies, ie)

			signals = append(signals, ie)
		}
	} else {
		size := len(asduBody) / int(asdu.nObjs)
		for i := 0; i < int(asdu.nObjs); i++ {
			io := &InformationObject{}
			io.parseIOA(asduBody[i*size : i*size+3])
			{
				ie := &InformationElement{
					TypeID:  asdu.typeID,
					Address: io.ioa,
				}
				asdu.parseInformationElement(asduBody[i*size+IOALength:(i+1)*size], ie)
				io.ies = []*InformationElement{ie}

				signals = append(signals, ie)
			}
			ios = append(ios, io)
		}
	}
}

const (
	IOALength = 3
)

type IOA uint32
