package iec104

import (
	"fmt"
)

const (
	ApduHeaderLen = 4 // non-include startByte and apduLen
	AsduHeaderLen = 6
)

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
	*APCI
	*ASDU

	frame       Frame
}

func (apdu *APDU) Parse(data []byte) error {
	if len(data) < ApduHeaderLen {
		return fmt.Errorf("invalid apdu body: % X", data)
	}

	// Parse APCI.
	apci := new(APCI)
	frame, err := apci.Parse(data[:ApduHeaderLen])
	if err != nil {
		return err
	}
	apdu.APCI = apci
	apdu.frame = frame

	switch frame.Type() {
	case FrameTypeS, FrameTypeU: // S-format or U-format frame doesn't have ASDU.
		return nil
	}

	// Parse ASDU.
	asdu := new(ASDU)
	if err = asdu.Parse(data[ApduHeaderLen:]); err != nil {
		return err
	}
	apdu.ASDU = asdu

	return nil
}
