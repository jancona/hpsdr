// Copyright 2020 James P. Ancona

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hpsdr

import "math"

// Radio represents an HPSDR radio
type Radio interface {
	Close()
	Device() Device
	// Receivers() []Receiver
	SendSamples([]TransmitSample) error
	SetOCOut(uint8)
	SetLNAGain(gain uint)
	SetSampleRate(speed uint) error
	SetTXFrequency(frequency uint)
	Start() error
	Stop() error
	TransmitSamplesPerMessage() uint
	// AddReceiver adds a new Receiver to the Radio and returns it
	AddReceiver(func([]ReceiveSample)) (Receiver, error)
}

// Receiver represents an HPSDR receiver
type Receiver interface {
	// SetFrequency sets the receiver center frequency
	SetFrequency(frequency uint)
	// GetFrequency returns the receiver center frequency
	GetFrequency() uint
	// Close closes the receiver
	Close() error
	// IsClosed returns true if the receiver has been closed
	IsClosed() bool
}

// ReceiveSample represents a single EP6 IQ sample from the radio
type ReceiveSample struct {
	I2 byte
	I1 byte
	I0 byte
	Q2 byte
	Q1 byte
	Q0 byte
	M1 byte
	M0 byte
}

// IFloat returns the I value as a float
func (rs ReceiveSample) IFloat() float32 {
	u := uint32(rs.I2)<<24 | uint32(rs.I1)<<16 | uint32(rs.I0)<<8
	i := int32(u)
	return float32(i) / (float32)(math.MaxInt32-256)
}

// QFloat returns the Q value as a float
func (rs ReceiveSample) QFloat() float32 {
	u := uint32(rs.Q2)<<24 | uint32(rs.Q1)<<16 | uint32(rs.Q0)<<8
	q := int32(u)
	return float32(q) / (float32)(math.MaxInt32-256)
}

// TransmitSample represents a single EP2 transmit sample sent to the radio
type TransmitSample struct {
	Left  uint16
	Right uint16
	I     uint16
	Q     uint16
}
