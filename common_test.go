package iec104

import "testing"

func Test_parseLittleEndianInt16(t *testing.T) {
	type args struct {
		x []byte
	}
	tests := []struct {
		name string
		args args
		want int16
	}{
		{
			"all bits are 0",
			args{
				[]byte{0x00, 0x00},
			},
			0,
		},
		{
			"all bits are 1",
			args{
				[]byte{0xff, 0xff},
			},
			-1,
		},
		{
			"only first byte is 0",
			args{
				[]byte{0x00, 0xff},
			},
			-256,
		},
		{
			"only first byte is 1",
			args{
				[]byte{0xff, 0x00},
			},
			255,
		},
		{
			"only first bit is 0",
			args{
				[]byte{0x7f, 0xff},
			},
			-129,
		},
		{
			"only first bit is 1",
			args{
				[]byte{0x80, 0x00},
			},
			128,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseLittleEndianInt16(tt.args.x); got != tt.want {
				t.Errorf("parseLittleEndianInt16() = %v, want %v", got, tt.want)
			}
		})
	}
}
