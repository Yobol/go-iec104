package iec104

import (
	"encoding/binary"
	"github.com/sirupsen/logrus"
)

var _lg = logrus.New()

func SetLogger(lg *logrus.Logger) {
	_lg = lg
}

func serializeBigEndianUint16(i uint16) []byte {
	bytes := make([]byte, 2, 2)
	binary.BigEndian.PutUint16(bytes, i)
	return bytes
}

func parseLittleEndianUint16(x []byte) uint16 {
	return binary.LittleEndian.Uint16(x)
}

func parseLittleEndianInt16(x []byte) int16 {
	return int16(parseLittleEndianUint16(x))
}

func serializeLittleEndianUint16(i uint16) []byte {
	bytes := make([]byte, 2, 2)
	binary.LittleEndian.PutUint16(bytes, i)
	return bytes
}

func parseLittleEndianUint32(x []byte) uint32 {
	return binary.LittleEndian.Uint32(x)
}

func parseLittleEndianInt32(x []byte) int32 {
	return int32(parseLittleEndianUint32(x))
}

func serializeLittleEndianUint32(i uint32) []byte {
	bytes := make([]byte, 4, 4)
	binary.LittleEndian.PutUint32(bytes, i)
	return bytes
}

type cmdRsp struct {
	err error
}
