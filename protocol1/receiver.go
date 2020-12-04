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
	number     byte
	sampleFunc func([]hpsdr.ReceiveSample)
}

// SetFrequency sets the receiver frequency
func (r *Receiver) SetFrequency(frequency uint) {
	r.radio.rxFrequency[r.number] = uint32(frequency)
}

// Close closes the receiver
func (r *Receiver) Close() error {
	if r.sampleFunc == nil {
		// Already closed!
		return errors.New("receiver already closed")
	}
	r.radio.receiverMutex.Lock()
	defer r.radio.receiverMutex.Unlock()
	delete(r.radio.receivers, r)
	if r.number > 0 {
		// Always keep one receiver
		r.radio.receiverCount--
	}
	r.sampleFunc = nil
	return nil
}
