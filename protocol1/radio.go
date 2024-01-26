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
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/jancona/hpsdr"
)

const (
	lastEP2Address  = 63
	samplesPerFrame = 63
	// TransmitSamplesPerMessage is the number of audio samples in a transmit message
	TransmitSamplesPerMessage = 2 * samplesPerFrame
)

// Metis start/stop commands
const (
	metisStartIQ        = 0b01
	metisStartBandscope = 0b10
	metisStop           = 0
)

// Radio is the current desired radio of the radio
type Radio struct {
	running bool
	device  *hpsdr.Device
	conn    *net.UDPConn
	// protocol state
	sendIQ        bool
	sendBandscope bool
	mox           bool
	// These are the HL2 address definitions from https://github.com/softerhardware/Hermes-Lite2/wiki/Protocol#base-memory-map
	// since that is all we aim to support for now.
	// 0x00	[25:24]	Speed (00=48kHz, 01=96kHz, 10=192kHz, 11=384kHz)
	speed byte // 0b00=48kHz, 0b01=96kHz, 0b10=192kHz, 0b11=384kHz
	// 0x00	[23:17]	Open Collector Outputs on Penelope or Hermes
	ocOut byte
	// 0x00	[13]	Control MCP23008 GP7 (I2C device on N2ADR filter board) (0=TX antenna, 1=RX antenna)
	rxAntenna bool // false=TX antenna, true=RX antenna
	// 0x00	[12]	FPGA-generated power supply switching clock (0=on, 1=off)
	clockOff bool // false=on, true=off
	// 0x00	[10]	VNA fixed RX Gain (0=-6dB, 1=+6dB)
	vnaGain bool // false=-6db, true=+6db
	// 0x00	[6:3]	Number of Receivers (0000=1 to max 1011=12)
	// receiverCount byte // 0b0000=1 to max 0b1011=12 - Note that this is number of receivers minus one
	// 0x00	[2]	Duplex (0=off, 1=on)
	duplex bool // false=off, true=on
	// 0x01	[31:0]	TX1 NCO Frequency in Hz
	txFrequency uint32
	// 0x02	[31:0]	RX1 NCO Frequency in Hz
	// 0x03	[31:0]	If present, RX2 NCO Frequency in Hz
	// 0x04	[31:0]	If present, RX3 NCO Frequency in Hz
	// 0x05	[31:0]	If present, RX4 NCO Frequency in Hz
	// 0x06	[31:0]	If present, RX5 NCO Frequency in Hz
	// 0x07	[31:0]	If present, RX6 NCO Frequency in Hz
	// 0x08	[31:0]	If present, RX7 NCO Frequency in Hz
	rxFrequency [12]uint32
	// 0x09	[31:24]	Hermes TX Drive Level (only [31:28] used)
	txDrive byte
	// 0x09	[23]	VNA mode (0=off, 1=on)
	vnaMode bool
	// 0x09	[22]	Alex manual mode (0=off, 1=on) (Not implemented yet)
	alexMode bool
	// 0x09	[20]	Tune request, set during TX spot or tune to initiate an ATU tune request
	tune bool
	// 0x09	[19]	Onboard PA (0=off, 1=on)
	paOn bool
	// 0x09	[18]	Q5 switch internal PTT in low power mode or 0=ATU tune and 1=ATU bypass when PA is on
	internalPTT bool
	// 0x09	[15:8]	I2C RX filter (Not implemented), or VNA count MSB
	// 0x09	[7:0]	I2C TX filter (Not implemented), or VNA count LSB
	vnaCount uint16
	// 0x0a	[22]	PureSignal (0=disable, 1=enable)
	pureSignal bool
	// 0x0a	[6]	See LNA gain section in https://github.com/softerhardware/Hermes-Lite2/wiki/Protocol#lna-gain
	hl2LNAMode bool // true=HL2 LNA mode, false=legacy Hermes mode
	// 0x0a	[5:0]	LNA[5:0] gain
	receiveLNAGain byte // When hermesLNAMode is false, valid values are between 0 (-12dB) and 60 (48dB)
	// 0x0e	[15]	Enable hardware managed LNA gain for TX
	hwTXLNA bool
	// 0x0e	[14]	See LNA gain section in https://github.com/softerhardware/Hermes-Lite2/wiki/Protocol#lna-gain
	// 0x0e	[13:8]	LNA[5:0] gain during TX if enabled
	// 0x0f	[24]	Enable CWX, I[0] of IQ stream is CWX keydown
	cwx bool
	// 0x10	[31:24]	CW Hang Time in ms, bits [9:2]
	// 0x10	[17:16]	CW Hang Time in ms, bits [1:0]
	cwHangTime uint16
	// 0x12	[31:0]	If present, RX8 NCO Frequency in Hz
	// 0x13	[31:0]	If present, RX9 NCO Frequency in Hz
	// 0x14	[31:0]	If present, RX10 NCO Frequency in Hz
	// 0x15	[31:0]	If present, RX11 NCO Frequency in Hz
	// 0x16	[31:0]	If present, RX12 NCO Frequency in Hz
	// See rxFrequency above
	// 0x17	[12:8]	PTT hang time, default is 4ms
	pttHangTime byte
	// 0x17	[6:0]	TX buffer latency in ms, default is 10ms
	txBufferLatency byte
	// 0x2b	[31:24]	Predistortion subindex
	preDistortionSubIndex byte
	// 0x2b	[19:16]	Predistortion
	preDistortion byte
	// 0x39	[27:24]	Misc Commands
	// 				0x0 No command
	// 				0x9 Disable watchdog timer
	disableWatchdog bool
	// 0x39	[23]	Enable update of locked receivers
	// 0x39	[21]	Lock RX12 to RX 11
	// 0x39	[20]	Lock RX10 to RX 9
	// 0x39	[19]	Lock RX8 to RX7
	// 0x39	[18]	Lock RX6 to RX5
	// 0x39	[17]	Lock RX4 to RX3
	// 0x39	[16]	Lock RX2 to RX1
	// 0x39	[11:8]	Master Commands
	// 				0x0 No command
	// 				0x8 Disable Master
	// 				0x9 Enable Master
	// 0x39	[7:4]	Synchronization Commands
	// 				0x0 No command
	// 				0x8 Reset all filter pipelines
	// 				0x9 Reset and align all NCOs
	// 0x39	[3:0]	Clock Generator Commands
	// 				0x0 No command
	// 				0x8 Synchronize clock outputs
	// 				0xA Disable CL2 clock output
	// 				0xB Enable CL2 clock output
	// 				0xC Disable CL1 clock input
	// 				0XD Enable CL1 clock input
	// 0x3a	[0]	Reset HL2 on disconnect
	resetOnDisconnect bool
	// 0x3b	[31:24]	AD9866 SPI cookie, must be 0x06 to write
	// 0x3b	[20:16]	AD9866 SPI address
	// 0x3b	[7:0]	AD9866 SPI data
	// 0x3c	[31:24]	I2C1 cookie, must be 0x06 to write, 0x07 to read
	// 0x3c	[23]	I2C1 stop at end (0=continue, 1=stop)
	// 0x3c	[22:16]	I2C1 target chip address
	// 0x3c	[15:8]	I2C1 control
	// 0x3c	[7:0]	I2C1 data (only for write)
	// 0x3d	[31:24]	I2C2 cookie, must be 0x06 to write, 0x07 to read
	// 0x3d	[23]	I2C2 stop at end (0=continue, 1=stop)
	// 0x3d	[22:16]	I2C2 target chip address
	// 0x3d	[15:8]	I2C2 control
	// 0x3d	[7:0]	I2C2 data (only for write)
	// 0x3f	[31:0]	Error for responses

	// These are the HL2 received address definitions (see https://github.com/softerhardware/Hermes-Lite2/wiki/Protocol#data-from-hermes-lite2-to-pc)
	// We always set ACK==0, so responses are in classic mode.
	// C0	[7]		ACK==0
	// 		[6:3]	RADDR[3:0]
	// 		[2]		Dot, see below
	// 		[1]		Dash, always zero
	// 		[0]		PTT, see below
	// C1	[7:0]	RDATA[31:24]
	// C2	[7:0]	RDATA[23:16]
	// C3	[7:0]	RDATA[15:8]
	// C4	[7:0]	RDATA[7:0]
	PTT bool
	// 0x00	[24]	RF ADC Overload
	ADCOverload bool
	// 0x00	[15]	Under/overflow Recovery**
	OverflowRecovery bool
	// 0x00	[14:8]	TX IQ FIFO Count MSBs

	// 0x00	[7:0]	Firmware Version
	FirmwareVersion byte
	// 0x01	[31:16]	Temperature
	Temperature uint16
	// 0x01	[15:0]	Forward Power
	ForwardPower uint16
	// 0x02	[31:16]	Reverse Power
	ReversePower uint16
	// 0x02	[15:0]	Current
	Current uint16

	// Message radio
	sentSeqNum         uint32
	lastReceivedSeqNum uint32

	nextEP2Address byte // Next EP2 address to send to. Value betwwen 0 and 64

	receiverMutex sync.Mutex  // Used when modifying or reading receivers
	receivers     []*Receiver // active receivers
}

// NewRadio creates a Protocol1Radio with reasonable defaults
func NewRadio(device *hpsdr.Device) *Radio {
	ret := Radio{
		sendIQ:    true,
		device:    device,
		receivers: []*Receiver{},
	}
	return &ret
}

// Device returns the device information
func (radio *Radio) Device() hpsdr.Device {
	return *radio.device
}

// SetSampleRate sets the sample rate in Hz. Valid values are 48000, 96000, 192000 or 384000
func (radio *Radio) SetSampleRate(speed uint) error {
	log.Printf("[DEBUG] SetSampleRate: %d", speed)
	switch speed {
	case 48000:
		radio.speed = 0b00
	case 96000:
		radio.speed = 0b01
	case 192000:
		radio.speed = 0b10
	case 384000:
		radio.speed = 0b11
	default:
		return fmt.Errorf("valid speed values are (48000, 96000, 192000, 384000), got %d", speed)
	}
	return nil
}

// SetOCOut set the open collector output bits
func (radio *Radio) SetOCOut(ocOut uint8) {
	radio.ocOut = ocOut
}

// SetTXFrequency sets the TX NCO frequency
func (radio *Radio) SetTXFrequency(frequency uint) {
	log.Printf("[DEBUG] SetTXFrequency: %d", frequency)
	radio.txFrequency = uint32(frequency)
}

// SetLNAGain sets the LNA gain. Valid values are between 0 (-12dB) and 60 (48dB)
func (radio *Radio) SetLNAGain(gain uint) {
	radio.hl2LNAMode = true
	if gain > 60 {
		gain = 60
	}
	radio.receiveLNAGain = byte(gain)
}

// TransmitSamplesPerMessage is the number of transmit samples per message
func (radio *Radio) TransmitSamplesPerMessage() uint {
	return TransmitSamplesPerMessage
}

// Start starts the radio
func (radio *Radio) Start() error {
	if !radio.sendIQ && !radio.sendBandscope {
		return errors.New("neither IQ nor bandscope are enabled")
	}
	var err error
	if radio.conn == nil {
		// Maybe we should bind to the discovered interface
		radio.conn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("error opening UDP connection: %w", err)
		}
	}
	err = radio.sendMetisCommand(metisStop)
	if err != nil {
		return fmt.Errorf("error sending stop command %w", err)
	}
	var frame1, frame2 [512]byte
	// initialize
	s := make([]hpsdr.TransmitSample, TransmitSamplesPerMessage)
	frame1, err = radio.buildEP2Frame(0x0, s[:samplesPerFrame])
	if err != nil {
		return err
	}
	frame2, err = radio.buildEP2Frame(0x1, s[samplesPerFrame:])
	if err != nil {
		return err
	}
	msg := radio.newMetisMessage(EP2, frame1, frame2)
	err = radio.writeMessage(msg)
	if err != nil {
		return err
	}
	frame1, err = radio.buildEP2Frame(0x0, s[:samplesPerFrame])
	if err != nil {
		return err
	}
	frame2, err = radio.buildEP2Frame(0x2, s[samplesPerFrame:])
	if err != nil {
		return err
	}
	msg = radio.newMetisMessage(EP2, frame1, frame2)
	err = radio.writeMessage(msg)
	if err != nil {
		return err
	}

	var cmd byte
	if radio.sendIQ {
		cmd |= metisStartIQ
	}
	if radio.sendBandscope {
		cmd |= metisStartBandscope
	}
	err = radio.sendMetisCommand(cmd)
	if err != nil {
		return fmt.Errorf("error sending start command %w", err)
	}
	go radio.receiveSamples()
	radio.running = true
	return nil
}

// Stop stops the radio
func (radio *Radio) Stop() error {
	err := radio.sendMetisCommand(metisStop)
	if err != nil {
		return fmt.Errorf("error sending stop command %w", err)
	}
	radio.running = false
	return nil
}

// Close the radio connection
func (radio *Radio) Close() {
	radio.Stop()
	radio.conn.Close()
}

// receiveSamples receives data from the radio
func (radio *Radio) receiveSamples() {
	for {
		// log.Printf("[DEBUG] receiveSamples()")
		// Receiving a message
		buffer := make([]byte, 2048)
		// log.Printf("[DEBUG] receiveSamples: local address %v, remote address %v", r.conn.LocalAddr(), r.conn.RemoteAddr())
		// radio.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		l, _, err := radio.conn.ReadFromUDP(buffer)
		if err != nil {
			if neterr, ok := err.(net.Error); ok {
				if operr, ok := neterr.(*net.OpError); ok {
					msg := fmt.Sprintf("receiveSamples: Error(): %s, Temporary(): %t, Timeout(): %t, Op: %s, Net: %s, Err: %#v",
						operr.Error(),
						operr.Temporary(),
						operr.Timeout(),
						operr.Op,
						operr.Net,
						operr.Err,
					)
					log.Print(msg)
				} else {
					log.Printf("receiveSamples: neterr: %#v", neterr)
				}
			} else {
				log.Printf("receiveSamples: Error reading from receiver: %#v", err)
			}
			return
		}
		mm := MetisMessage{}
		mm.EF = buffer[0]
		mm.FE = buffer[1]
		mm.ID01 = buffer[2]
		mm.EndPoint = metisEndpoint(buffer[3])
		mm.SequenceNumber = binary.BigEndian.Uint32(buffer[4:8])
		copy(mm.Frame1[:], buffer[8:8+512])
		if l >= 8+512 {
			copy(mm.Frame2[:], buffer[8+512:l])
		} else {
			log.Printf("receiveSamples: Short read: %d", l)
		}

		radio.receiverMutex.Lock()
		s, err := radio.decodeSamples(mm.Frame1)
		if err != nil {
			log.Printf("receiveSamples: error decoding Frame1 samples: %v", err)
		}
		for n, r := range radio.receivers {
			r.sampleFunc(s[n])
		}
		if l >= 8+512 {
			s, err = radio.decodeSamples(mm.Frame2)
			if err != nil {
				log.Printf("receiveSamples: error decoding Frame2 samples: %v", err)
			}
		}
		for n, r := range radio.receivers {
			r.sampleFunc(s[n])
		}
		radio.receiverMutex.Unlock()
		// log.Printf("[DEBUG] receiveSamples: %#v", *mm)
	}
}

type ep6Data struct {
	Sync       [3]byte
	C0         byte
	C1         byte
	C2         byte
	C3         byte
	C4         byte
	SampleData [samplesPerFrame * 8]byte
	// Samples [samplesPerFrame]hpsdr.ReceiverSample
}

func (radio *Radio) decodeSamples(frame [512]byte) ([][]hpsdr.ReceiveSample, error) {
	var packet ep6Data

	copy(packet.Sync[:], frame[0:3])
	i := 3
	packet.C0 = frame[i]
	i++
	packet.C1 = frame[i]
	i++
	packet.C2 = frame[i]
	i++
	packet.C3 = frame[i]
	i++
	packet.C4 = frame[i]
	i++
	copy(packet.SampleData[:], frame[i:i+samplesPerFrame*8])
	// sanity check
	if packet.Sync[0] != 0x7f || packet.Sync[1] != 0x7f || packet.Sync[2] != 0x7f {
		return nil, fmt.Errorf("received corrupted EP6 frame. Incorrect Sync bytes: %#v", packet)
	}
	if (packet.C0 & 0b10000000) != 0 {
		return nil, fmt.Errorf("received EP6 frame with ACK set: %#v", packet)
	}
	radio.PTT = (packet.C0 & 0b1) != 0
	addr := (packet.C0 & 0b01111000) >> 3
	rdata := uint32(packet.C1) << 24
	rdata |= uint32(packet.C2) << 16
	rdata |= uint32(packet.C3) << 8
	rdata |= uint32(packet.C4)
	switch addr {
	case 0x00:
		radio.ADCOverload = (rdata & 1 << 24) != 0
		radio.OverflowRecovery = (rdata & 1 << 15) != 0
		radio.FirmwareVersion = byte(rdata & 0xff)
		// log.Printf("[DEBUG] ADCOverload: %v, OverflowRecovery: %v, FirmwareVersion: %v", radio.ADCOverload, radio.OverflowRecovery, radio.FirmwareVersion)
	case 0x01:
		radio.ForwardPower = uint16(rdata & 0xffff)
		radio.Temperature = uint16((rdata >> 16) & 0xffff)
		// log.Printf("[DEBUG] ForwardPower: %v, Temperature: %v", radio.ForwardPower, radio.Temperature)
	case 0x02:
		radio.Current = uint16(rdata & 0xffff)
		radio.ReversePower = uint16((rdata >> 16) & 0xffff)
	}
	// The mutex is managed in the caller, receiveSamples()
	// radio.receiverMutex.Lock()
	// defer radio.receiverMutex.Unlock()
	samples := make([][]hpsdr.ReceiveSample, len(radio.receivers))
	samplesPerMessage := (512 - 8) / (len(radio.receivers)*6 + 2)
	for i := range samples {
		samples[i] = make([]hpsdr.ReceiveSample, samplesPerMessage)
	}

	n := 0
	for i := 0; i < samplesPerMessage; i++ {
		for j := 0; j < len(radio.receivers); j++ {
			samples[j][i].I2 = packet.SampleData[n]
			n++
			samples[j][i].I1 = packet.SampleData[n]
			n++
			samples[j][i].I0 = packet.SampleData[n]
			n++
			samples[j][i].Q2 = packet.SampleData[n]
			n++
			samples[j][i].Q1 = packet.SampleData[n]
			n++
			samples[j][i].Q0 = packet.SampleData[n]
			n++
		}
		m1 := packet.SampleData[n]
		n++
		m0 := packet.SampleData[n]
		n++
		for j := 0; j < len(radio.receivers); j++ {
			samples[j][i].M1 = m1
			samples[j][i].M0 = m0
		}
	}
	return samples, nil
}

func assemble(hi, mid, lo byte) uint32 {
	return uint32(lo) | uint32(mid)<<8 | uint32(hi)<<16
}

// SendSamples send data to the radio and updates its radio
func (radio *Radio) SendSamples(samples []hpsdr.TransmitSample) error {
	// Eventually we should buffer until we have enough to send a packet.
	// For now, if we dont have have a multiple of 126 samples, we send what we have and pad with empty ones
	var frame1, frame2 [512]byte
	var err error

	s := samples
	if len(samples) < TransmitSamplesPerMessage {
		s = make([]hpsdr.TransmitSample, TransmitSamplesPerMessage)
		copy(s, samples)
	}

	frame1, err = radio.buildEP2Frame(radio.nextEP2Address, s[:samplesPerFrame])
	if err != nil {
		return err
	}
	if radio.nextEP2Address < lastEP2Address {
		radio.nextEP2Address++
	} else {
		radio.nextEP2Address = 0
	}

	frame2, err = radio.buildEP2Frame(radio.nextEP2Address, s[samplesPerFrame:])
	if err != nil {
		return err
	}
	if radio.nextEP2Address < lastEP2Address {
		radio.nextEP2Address++
	} else {
		radio.nextEP2Address = 0
	}
	msg := radio.newMetisMessage(EP2, frame1, frame2)

	err = radio.writeMessage(msg)
	if err != nil {
		return err
	}
	return nil
}

func (radio *Radio) writeMessage(msg MetisMessage) error {
	buf := make([]byte, 1032)
	i := 0
	buf[i] = msg.EF
	i++
	buf[i] = msg.FE
	i++
	buf[i] = msg.ID01
	i++
	buf[i] = byte(msg.EndPoint)
	i++
	binary.BigEndian.PutUint32(buf[i:i+4], msg.SequenceNumber)
	i += 4
	copy(buf[i:i+512], msg.Frame1[:])
	i += 512
	copy(buf[i:i+512], msg.Frame2[:])
	_, err := radio.conn.WriteToUDP(buf, radio.device.Network.Address)
	// _, err = radio.conn.WriteToUDP(buf.Bytes(), radio.device.Network.Address)
	if err != nil {
		return err
	}
	// log.Printf("[DEBUG] Sent %d byte EP2 message", cnt)
	return nil
}

// receiverIndex returns the ordinal index of the passed receiver, or -1 if the receiver is not valid
func (radio *Radio) receiverIndex(rec *Receiver) int {
	radio.receiverMutex.Lock()
	defer radio.receiverMutex.Unlock()
	for n, r := range radio.receivers {
		if r == rec {
			return n
		}
	}
	return -1
}

// AddReceiver adds a new Receiver to the Radio and returns it.
func (radio *Radio) AddReceiver(sampleFunc func([]hpsdr.ReceiveSample)) (hpsdr.Receiver, error) {
	radio.receiverMutex.Lock()
	defer radio.receiverMutex.Unlock()
	if len(radio.receivers) >= radio.device.SupportedReceivers {
		return nil, errors.New("maximum number of receivers already in use")
	}
	r := &Receiver{radio, sampleFunc}
	radio.receivers = append(radio.receivers, r)
	return r, nil
}

func (radio *Radio) deleteReceiver(rec *Receiver) {
	radio.receiverMutex.Lock()
	defer radio.receiverMutex.Unlock()
	log.Printf("[DEBUG] Attempting to delete receiver %#v", *rec)
	for n, r := range radio.receivers {
		if r == rec {
			log.Printf("[DEBUG] Deleting receiver %#v", *rec)
			log.Printf("[DEBUG] radio.receivers: %#v, radio.rxFrequency: %#v before", radio.receivers, radio.rxFrequency)
			// remove matching receiver and move following elements to the left
			radio.receivers = append(radio.receivers[:n], radio.receivers[n+1:]...)
			// radio.rxFrequency is a 12 element array instead of a slice, so we
			// remove matching frequency and move following elements to the left, plus add a zero padding at the end
			slice := append(append(radio.rxFrequency[:n], radio.rxFrequency[n+1:]...), 0)
			// copy slice back into rxFrequency array
			copy(radio.rxFrequency[:], slice)
			log.Printf("[DEBUG] radio.receivers: %#v, radio.rxFrequency: %#v after", radio.receivers, radio.rxFrequency)
			if n == 0 {
				radio.SetTXFrequency(uint(radio.rxFrequency[n]))
			}
			return
		}
	}
	log.Printf("[DEBUG] Failed to delete receiver %v (%v) from %#v", *rec, rec, radio.receivers)
}

type ep2Data struct {
	Sync    [3]byte
	C0      byte
	C1      byte
	C2      byte
	C3      byte
	C4      byte
	Samples [samplesPerFrame]hpsdr.TransmitSample
}

func (radio *Radio) buildEP2Frame(ep2Address byte, samples []hpsdr.TransmitSample) ([512]byte, error) {
	arr := [512]byte{}
	data := ep2Data{
		Sync: [3]byte{0x7F, 0x7F, 0x7F},
	}
	copy(data.Samples[:], samples)

	var tdata uint32
	switch ep2Address {
	case 0x00:
		tdata |= uint32(radio.speed&0b11) << 24
		tdata |= uint32(radio.ocOut&0b1111111) << 17
		if radio.rxAntenna {
			tdata |= 1 << 13
		}
		if radio.clockOff {
			tdata |= 1 << 12
		}
		if radio.vnaGain {
			tdata |= 1 << 10
		}
		radio.receiverMutex.Lock()
		receiverCount := 0
		if len(radio.receivers) > 0 {
			receiverCount = len(radio.receivers) - 1
		}
		radio.receiverMutex.Unlock()
		tdata |= uint32(receiverCount) << 3
		if radio.duplex {
			tdata |= 1 << 2
		}
	case 0x01:
		tdata = radio.txFrequency
	case 0x02:
		// log.Printf("[DEBUG] Set rx1Frequency to %d", radio.rx1Frequency)
		tdata = radio.rxFrequency[0]
	case 0x03:
		tdata = radio.rxFrequency[1]
	case 0x04:
		tdata = radio.rxFrequency[2]
	case 0x05:
		tdata = radio.rxFrequency[3]
	case 0x06:
		tdata = radio.rxFrequency[4]
	case 0x07:
		tdata = radio.rxFrequency[5]
	case 0x08:
		tdata = radio.rxFrequency[6]
	case 0x09:
		tdata |= uint32(radio.txDrive) >> 24
		if radio.vnaMode {
			tdata |= 1 << 23
		}
		if radio.alexMode {
			tdata |= 1 << 22
		}
		if radio.tune {
			tdata |= 1 << 20
		}
		if radio.paOn {
			tdata |= 1 << 19
		}
		tdata |= uint32(radio.vnaCount)
	case 0x0a:
		if radio.pureSignal {
			tdata |= 1 << 22
		}
		if radio.hl2LNAMode {
			tdata |= 1 << 6
			tdata |= uint32(radio.receiveLNAGain)
		} else {
			// not implemented
		}
	case 0x0e:
		if radio.hwTXLNA {
			tdata |= 1 << 15
		}
		// Other TX LNA gain not implemented
	case 0x0f:
		// CWX not implemented
	case 0x10:
		// CW hang time not implemented
	case 0x12:
		tdata = radio.rxFrequency[7]
	case 0x13:
		tdata = radio.rxFrequency[8]
	case 0x14:
		tdata = radio.rxFrequency[9]
	case 0x15:
		tdata = radio.rxFrequency[10]
	case 0x16:
		tdata = radio.rxFrequency[11]
	case 0x17:
		tdata |= uint32(radio.pttHangTime) << 8
		tdata |= uint32(radio.txBufferLatency)
	case 0x2b:
		tdata |= uint32(radio.preDistortionSubIndex) << 24
		tdata |= uint32(radio.preDistortion) << 16
		// Rest of commands not implemented
	}

	data.C0 = 0
	if radio.mox {
		data.C0 |= 0x01
	}
	data.C0 |= ep2Address << 1
	data.C1 = byte(tdata >> 24)
	data.C2 = byte(tdata >> 16)
	data.C3 = byte(tdata >> 8)
	data.C4 = byte(tdata)
	// log.Printf("[DEBUG] Sending address: %02x, %d (decimal)\n\t\t\tdata.C0=%02x, data.C1=%02x, data.C2=%02x, data.C3=%02x, data.C4=%02x", ep2Address, tdata, data.C0, data.C1, data.C2, data.C3, data.C4)

	i := 0
	copy(arr[i:3], data.Sync[:])
	i += 3
	arr[i] = data.C0
	i++
	arr[i] = data.C1
	i++
	arr[i] = data.C2
	i++
	arr[i] = data.C3
	i++
	arr[i] = data.C4
	i++
	for _, s := range data.Samples {
		binary.BigEndian.PutUint16(arr[i:i+2], s.Left)
		i += 2
		binary.BigEndian.PutUint16(arr[i:i+2], s.Right)
		i += 2
		binary.BigEndian.PutUint16(arr[i:i+2], s.I)
		i += 2
		binary.BigEndian.PutUint16(arr[i:i+2], s.Q)
		i += 2
	}
	if i != 512 {
		return arr, fmt.Errorf("built incorrect length EP2 frame (should be 512, was %d)", i)
	}
	return arr, nil
}

func (radio *Radio) sendMetisCommand(command byte) error {
	buf := make([]byte, 64)
	buf[0] = 0xEF
	buf[1] = 0xFE
	buf[2] = 0x04
	buf[3] = command
	_, err := radio.conn.WriteToUDP(buf, radio.device.Network.Address)
	if err != nil {
		return err
	}
	// log.Printf("[DEBUG] Sent %d byte command", cnt)
	return nil
}

type metisEndpoint byte

// Valid metisEndpoint values
const (
	EP2 metisEndpoint = 0x2 // PC->Radio: Command and Control plus two audio streams
	EP4 metisEndpoint = 0x4 // Radio->PC: Bandscope data
	EP6 metisEndpoint = 0x6 // Radio->PC: IQ + microphone data
)

// MetisMessage represents a message sent to or from the radio
type MetisMessage struct {
	EF             byte
	FE             byte
	ID01           byte // If we were doing bootloader operations, we would need to be able to set this
	EndPoint       metisEndpoint
	SequenceNumber uint32
	Frame1         [512]byte
	Frame2         [512]byte
}

// newMetisMessage builds a new Metis message for sending
func (radio *Radio) newMetisMessage(endPoint metisEndpoint, frame1, frame2 [512]byte) MetisMessage {
	ret := MetisMessage{
		EF:             0xEF,
		FE:             0xFE,
		ID01:           0x01,
		EndPoint:       endPoint,
		SequenceNumber: radio.sentSeqNum,
		Frame1:         frame1,
		Frame2:         frame2,
	}
	radio.sentSeqNum++
	return ret
}
