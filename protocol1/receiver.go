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

package protocol1

import (
	"errors"

	"github.com/jancona/hpsdr"
)

// Receiver is a receiver on a Protocol1Radio
type Receiver struct {
	radio      *Radio
	sampleFunc func([]hpsdr.ReceiveSample)
}

// SetFrequency sets the receiver frequency
func (rec *Receiver) SetFrequency(frequency uint) {
	rec.radio.receiverMutex.Lock()
	defer rec.radio.receiverMutex.Unlock()
	index := rec.radio.receiverIndex(rec)
	rec.radio.rxFrequency[index] = uint32(frequency)
	if index == 0 {
		rec.radio.SetTXFrequency(frequency)
	}
}

// GetFrequency returns the receiver center frequency
func (rec *Receiver) GetFrequency() uint {
	rec.radio.receiverMutex.Lock()
	defer rec.radio.receiverMutex.Unlock()
	index := rec.radio.receiverIndex(rec)
	return uint(rec.radio.rxFrequency[index])
}

// Close closes the receiver
func (rec *Receiver) Close() error {
	rec.radio.deleteReceiver(rec)
	if rec.IsClosed() {
		// Already closed!
		return errors.New("receiver already closed")
	}
	rec.sampleFunc = nil
	return nil
}

// IsClosed returns true if the receiver has been closed
func (rec *Receiver) IsClosed() bool {
	return rec.sampleFunc == nil
}
