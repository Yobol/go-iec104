package iec104

import "testing"

func TestInformationObject_parseIOA(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want IOA
	}{
		{
			"all bits are 1",
			args{
				[]byte{0x11, 0x11, 0x11, 0xff},
			},
			IOA(0x111111),
		},
		{
			"all bits are 0",
			args{
				[]byte{0x00, 0x00, 0x00, 0xff},
			},
			IOA(0x000000),
		},
		{
			"only first byte bits are 1",
			args{
				[]byte{0x11, 0x00, 0x00, 0xff},
			},
			IOA(0x000011),
		},
		{
			"only first byte bits are 0",
			args{
				[]byte{0x00, 0x11, 0x11, 0xff},
			},
			IOA(0x111100),
		},
		{
			"only first bit are 1",
			args{
				[]byte{0x80, 0x00, 0x00, 0xff},
			},
			IOA(0x000080),
		},
		{
			"only first bit are 0",
			args{
				data: []byte{0x7f, 0xff, 0xff, 0xff},
			},
			IOA(0xffff7f),
		},

		{
			"1",
			args{
				[]byte{0x01, 0x00, 0x00, 0xff},
			},
			IOA(1),
		},
		{
			"1024",
			args{
				[]byte{0x00, 0x04, 0x00, 0xff},
			},
			IOA(1024),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &InformationObject{}
			i.parseIOA(tt.args.data)
			if got := i.ioa; got != tt.want {
				t.Errorf("parseIOA() = %v, want %v", got, tt.want)
			}
			if tt.args.data[3] != 0xff {
				t.Errorf("reading IOA can't change data[3], it must be 0xff!")
			}
		})
	}
}
