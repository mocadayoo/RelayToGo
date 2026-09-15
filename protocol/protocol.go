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

	MsgTunnelAdd    MessageType = "tunnel_add"
	MsgTunnelRemove MessageType = "tunnel_remove"
	MsgTunnelAck    MessageType = "tunnel_ack"
	MsgTunnelCreate MessageType = "tunnel_create"
	MsgTunnelDelete MessageType = "tunnel_delete"
	MsgTunnelResult MessageType = "tunnel_result"
)

type Mapping struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Network    Network `json:"network"`
	PublicPort uint16  `json:"public_port"`
	MappingID  uint64  `json:"mapping_id"`
	TargetAddr string  `json:"target_addr"`
}

type Message struct {
	Type            MessageType `json:"type"`
	Mappings        []Mapping   `json:"mappings,omitempty"`
	Tunnel          *Mapping    `json:"tunnel,omitempty"`
	TunnelID        string      `json:"tunnel_id,omitempty"`
	RequestID       string      `json:"request_id,omitempty"`
	RelayPublicAddr string      `json:"relay_public_addr,omitempty"`
	Reason          string      `json:"reason,omitempty"`
}

func MarshalUDPDatagram(port uint16, mappingID, flowID uint64, payload []byte) ([]byte, error) {
	packet := make([]byte, 18+len(payload))
	binary.BigEndian.PutUint16(packet[:2], port)
	binary.BigEndian.PutUint64(packet[2:10], mappingID)
	binary.BigEndian.PutUint64(packet[10:18], flowID)
	copy(packet[18:], payload)
	return packet, nil
}

func UnmarshalUDPDatagram(packet []byte) (port uint16, mappingID, flowID uint64, payload []byte, err error) {
	if len(packet) < 18 {
		err = fmt.Errorf("UDP datagram header is truncated")
		return
	}

	port = binary.BigEndian.Uint16(packet[:2])
	mappingID = binary.BigEndian.Uint64(packet[2:10])
	flowID = binary.BigEndian.Uint64(packet[10:18])
	payload = packet[18:]
	return
}
