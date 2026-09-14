package protocol

import (
	"encoding/binary"
	"fmt"
)

type Network string

const (
	NetworkTCP Network = "tcp"
	NetworkUDP Network = "udp"
)

type MessageType string

const (
	MsgRegister   MessageType = "register"
	MsgRegistered MessageType = "registered"
	MsgOpenTCP    MessageType = "open_tcp"
	MsgError      MessageType = "error"
	MsgPing       MessageType = "ping"
	MsgPong       MessageType = "pong"
)

type Mapping struct {
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

func MarshalUDPDatagram(port uint16, address string, payload []byte) ([]byte, error) {
	if len(address) > 0xffff {
		return nil, fmt.Errorf("address is too long")
	}

	packet := make([]byte, 4+len(address)+len(payload))
	binary.BigEndian.PutUint16(packet[:2], port)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(address)))
	copy(packet[4:], address)
	copy(packet[4+len(address):], payload)
	return packet, nil
}

func UnmarshalUDPDatagram(packet []byte) (port uint16, address string, payload []byte, err error) {
	if len(packet) < 4 {
		err = fmt.Errorf("UDP datagram header is truncated")
		return
	}

	port = binary.BigEndian.Uint16(packet[:2])
	addrLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if len(packet) < 4+addrLen {
		err = fmt.Errorf("UDP datagram address is truncated")
		return
	}

	address = string(packet[4 : 4+addrLen])
	payload = packet[4+addrLen:]
	return
}
