package iec104

import "testing"

var asdu = &ASDU{}

func TestParseTypeID(t *testing.T) {
	type args struct {
		data byte
	}
	tests := []struct {
		name string
		args args
		want TypeID
	}{
		{
			"all bits are 0",
			args{
				0b00000000,
			},
			0,
		},
		{
			"all bits are 1",
			args{
				0b11111111,
			},
			255,
		},
		{
			"only first bit is 0",
			args{
				0b01111111,
			},
			127,
		},
		{
			"only first bit is 1",
			args{
				0b10000000,
			},
			128,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asdu.parseTypeID(tt.args.data); got != tt.want {
				t.Errorf("ParseTypeID() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestParseSQ(t *testing.T) {
	type args struct {
		data byte
	}
	tests := []struct {
		name string
		args args
		want SQ
	}{
		{
			"all bits are 0",
			args{
				0b00000000,
			},
			false,
		},
		{
			"all bits are 1",
			args{
				0b11111111,
			},
			true,
		},
		{
			"only first bit is 0",
			args{
				0b01111111,
			},
			false,
		},
		{
			"only first bit is 1",
			args{
				0b10000000,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asdu.parseSQ(tt.args.data); got != tt.want {
				t.Errorf("ParseSQ() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestParseNOO(t *testing.T) {
	type args struct {
		data byte
	}
	tests := []struct {
		name string
		args args
		want NOO
	}{
		{
			"all bits are 0",
			args{
				0b00000000,
			},
			0,
		},
		{
			"all bits are 1",
			args{
				0b11111111,
			},
			127,
		},
		{
			"only first bit is 0",
			args{
				0b01111111,
			},
			127,
		},
		{
			"only first bit is 1",
			args{
				0b10000000,
			},
			0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asdu.parseNOO(tt.args.data); got != tt.want {
				t.Errorf("ParseNOO() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestParseT(t *testing.T) {
	type args struct {
		data byte
	}
	tests := []struct {
		name string
		args args
		want T
	}{
		{
			"all bits are 0",
			args{
				0b00000000,
			},
			false,
		},
		{
			"all bits are 1",
			args{
				0b11111111,
			},
			true,
		},
		{
			"only first bit is 0",
			args{
				0b01111111,
			},
			false,
		},
		{
			"only first bit is 1",
			args{
				0b10000000,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asdu.parseT(tt.args.data); got != tt.want {
				t.Errorf("ParseT() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestParsePN(t *testing.T) {
	type args struct {
		data byte
	}
	tests := []struct {
		name string
		args args
		want PN
	}{
		{
			"all bits are 0",
			args{
				0b00000000,
			},
			false,
		},
		{
			"all bits are 1",
			args{
				0b11111111,
			},
			true,
		},
		{
			"only first bit is 0",
			args{
				0b01111111,
			},
			true,
		},
		{
			"only first bit is 1",
			args{
				0b10000000,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asdu.parsePN(tt.args.data); got != tt.want {
				t.Errorf("ParsePN() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestParseCOT(t *testing.T) {
	type args struct {
		data byte
	}
	tests := []struct {
		name string
		args args
		want COT
	}{
		{
			"all bits are 0",
			args{
				0b00000000,
			},
			0,
		},
		{
			"all bits are 1",
			args{
				0b11111111,
			},
			63,
		},
		{
			"only first bit is 0",
			args{
				0b01111111,
			},
			63,
		},
		{
			"only first bit is 1",
			args{
				0b10000000,
			},
			0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asdu.parseCOT(tt.args.data); got != tt.want {
				t.Errorf("ParseCOT() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestParseORG(t *testing.T) {
	type args struct {
		data byte
	}
	tests := []struct {
		name string
		args args
		want ORG
	}{
		{
			"all bits are 0",
			args{
				0b00000000,
			},
			0b00000000,
		},
		{
			"all bits are 1",
			args{
				0b11111111,
			},
			0b11111111,
		},
		{
			"only first bit is 0",
			args{
				0b01111111,
			},
			0b01111111,
		},
		{
			"only first bit is 1",
			args{
				0b10000000,
			},
			0b10000000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asdu.parseORG(tt.args.data); got != tt.want {
				t.Errorf("ParseORG() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestParseCOA(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want COA
	}{
		{
			"all bits are 0",
			args{
				[]byte{0b00000000, 0b00000000},
			},
			0,
		},
		{
			"all bits are 1",
			args{
				[]byte{0b11111111, 0b11111111},
			},
			65535,
		},
		{
			"first byte's all bits are 0",
			args{
				[]byte{0b00000000, 0b11111111}, // 1111111100000000
			},
			65280,
		},
		{
			"first byte's all bits are 1",
			args{
				[]byte{0b11111111, 0b00000000}, // 0000000011111111
			},
			255,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asdu.parseCOA(tt.args.data); got != tt.want {
				t.Errorf("ParseORG() = %v, want %v", got, tt.want)
			}
		})
	}
}
