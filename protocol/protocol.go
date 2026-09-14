package protocol

import (
	"encoding/binary"
	"fmt"
)

type Network string

const (
	NetworkTCP  Network = "tcp"
	NetworkUDP  Network = "udp"
	NetworkBoth Network = "both"
)

type MessageType string

const (
	MsgRegister   MessageType = "register"
	MsgRegistered MessageType = "registered"
	MsgOpenTCP    MessageType = "open_tcp"
	MsgError      MessageType = "error"
	MsgPing       MessageType = "ping"
	MsgPong       MessageType = "pong"
	MsgClose      MessageType = "close"
)

type Mapping struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Network    Network `json:"network"`
	PublicPort uint16  `json:"public_port"`
	TargetAddr string  `json:"target_addr"`
}

type Message struct {
	Type            MessageType `json:"type"`
	AgentID         string      `json:"agent_id,omitempty"`
	Token           string      `json:"token,omitempty"`
	Mappings        []Mapping   `json:"mappings,omitempty"`
	RelayPublicAddr string      `json:"relay_public_addr,omitempty"`
	MappingID       uint32      `json:"mapping_id,omitempty"`
	Reason          string      `json:"reason,omitempty"`
}

func MarshalUDPDatagram(port uint16, flowID uint64, payload []byte) ([]byte, error) {
	packet := make([]byte, 10+len(payload))
	binary.BigEndian.PutUint16(packet[:2], port)
	binary.BigEndian.PutUint64(packet[2:10], flowID)
	copy(packet[10:], payload)
	return packet, nil
}

func UnmarshalUDPDatagram(packet []byte) (port uint16, flowID uint64, payload []byte, err error) {
	if len(packet) < 10 {
		err = fmt.Errorf("UDP datagram header is truncated")
		return
	}

	port = binary.BigEndian.Uint16(packet[:2])
	flowID = binary.BigEndian.Uint64(packet[2:10])
	payload = packet[10:]
	return
}
