package iec104

import "fmt"

/*
APDU (Application Protocol Data Unit).

APDU contains an APCI or an APCI with ASDU.

  | <-   8 bits    -> |  -----    -----
  | Start Byte (Ox68) |    |        |
  | Length of APDU    |    |        |
  | Control Field 1   |   APCI     APDU
  | Control Field 2   |    |        |
  | Control Field 3   |    |        |
  | Control Field 4   |    |        |
  | <-   8 bits    -> |  -----    -----
  <-      APDU with fixed length     ->


  | <-   8 bits    -> |  -----    -----
  | Start Byte (Ox68) |    |        |
  | Length of APDU    |    |        |
  | Control Field 1   |   APCI     APDU
  | Control Field 2   |    |        |
  | Control Field 3   |    |        |
  | Control Field 4   |    |        |
  | ASDU              |   ASDU      |
  | <-   8 bits    -> |  -----    -----
  <-    APDU with variable length    ->

*/
type APDU struct {
	APCI *APCI
	ASDU *ASDU
}

func (apdu *APDU) Parse(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("invalid apdu body: % X", data)
	}

	apci := &APCI{
		ApduLen: uint8(len(data)),
		Cf1:     data[0],
		Cf2:     data[1],
		Cf3:     data[2],
		Cf4:     data[3],
	}
	apdu.APCI = apci
	return nil
}
