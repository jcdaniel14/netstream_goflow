package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	decoder "github.com/cloudflare/goflow/decoders"
	"github.com/cloudflare/goflow/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	reuseport "github.com/libp2p/go-reuseport"
	"github.com/prometheus/client_golang/prometheus"
)

func GetServiceAddresses(srv string) (addrs []string, err error) {
	_, srvs, err := net.LookupSRV("", "", srv)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Service discovery: %v\n", err))
	}
	for _, srv := range srvs {
		addrs = append(addrs, net.JoinHostPort(srv.Target, strconv.Itoa(int(srv.Port))))
	}
	return addrs, nil
}

type Logger interface {
	Printf(string, ...interface{})
	Errorf(string, ...interface{})
	Warnf(string, ...interface{})
	Warn(...interface{})
	Error(...interface{})
	Debug(...interface{})
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Fatalf(string, ...interface{})
}

type BaseMessage struct {
	Src     net.IP
	Port    int
	Payload []byte
}

type Transport interface {
	Publish([]*flowmessage.FlowMessage)
}

type DefaultLogTransport struct {
}

// Flow Structure needed to send to ElasticSearch
type Flow struct {
	Exporter  string `json:"flow.exporter"`
	FlowStart string `json:"flow.first_switched"`
	FlowEnd   string `json:"flow.last_switched"`
	Bytes     uint64 `json:"flow.bytes"`
	Packets   uint64 `json:"flow.packets"`
	SrcAddr   string `json:"flow.src_addr"`
	DstAddr   string `json:"flow.dst_addr"`
	Protocol  uint32 `json:"flow.protocol"`
	IPVersion string `json:"flow.ip_version"`
	SrcPort   uint32 `json:"flow.src_port"`
	DstPort   uint32 `json:"flow.dst_port"`
	IfName    string `json:"flow.input_ifname"`
	SrcMask   uint32 `json:"flow.src_mask"`
	DstMask   uint32 `json:"flow.dst_mask"`
}

//func sendToLogstash(msg *flowmessage.FlowMessage) {
//	ctx := context.Background()
//	// Ping the Elasticsearch server to get e.g. the version number
//	info, code, err := gl.Eclient.Ping("http://172.24.4.154:9200").Do(ctx)
//
//	if err != nil {
//		// Handle error
//		panic(err)
//	}
//
//	fmt.Printf("Elasticsearch returned with code %d and version %s\n", code, info.Version.Number)
//
//	t := time.Now().Local()
//	myIndex := "gsflow-" + t.Format("2006-01-02")
//	rate := uint64(1000)
//	ipVersion := ""
//	exporter := net.IP(msg.SamplerAddress).String()
//	flowStart := msg.TimeFlowStart
//	flowEnd := msg.TimeFlowEnd
//	srcAddr := net.IP(msg.SrcAddr).String()
//	dstAddr := net.IP(msg.DstAddr).String()
//	proto := msg.Proto
//	srcPort := msg.SrcPort
//	dstPort := msg.DstPort
//	srcIf := "Bundle-Ether90"
//	srcMask := msg.SrcNet
//	dstMask := msg.DstNet
//	if strings.Contains(srcAddr, ":") {
//		ipVersion = "IPv6"
//	} else {
//		ipVersion = "IPv4"
//	}
//	firstSw := time.Unix(int64(flowStart), 0).UTC().Format("2006-01-02T15:04:05.000")
//	lastSw := time.Unix(int64(flowEnd), 0).UTC().Format("2006-01-02T15:04:05.000")
//
//	flow := Flow{Exporter: exporter, FlowStart: firstSw, FlowEnd: lastSw, Bytes: msg.Bytes * rate, Packets: msg.Packets * rate, SrcAddr: srcAddr, DstAddr: dstAddr, Protocol: proto, IPVersion: ipVersion, SrcPort: srcPort, DstPort: dstPort, IfName: srcIf, SrcMask: srcMask, DstMask: dstMask}
//	put1, err := gl.Eclient.Index().
//		Index(myIndex).
//		Type("_doc").
//		BodyJson(flow).
//		Do(ctx)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Printf("Indexed flow %s to index %s, type %s\n", put1.Id, put1.Index, put1.Type)
//
//	// Flush to make sure the documents got written.
//	_, err = gl.Eclient.Flush().Index(myIndex).Do(ctx)
//	if err != nil {
//		panic(err)
//	}
//}

func (s *DefaultLogTransport) Publish(msgs []*flowmessage.FlowMessage) {

	for _, msg := range msgs {
		fmt.Printf("%v\n", FlowMessageToString(msg))
		// sendToLogstash(msg)
	}
}

type DefaultJSONTransport struct {
}

func (s *DefaultJSONTransport) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		fmt.Printf("%v\n", FlowMessageToJSON(msg))
	}
}

type DefaultErrorCallback struct {
	Logger Logger
}

func (cb *DefaultErrorCallback) Callback(name string, id int, start, end time.Time, err error) {
	if _, ok := err.(*netflow.ErrorTemplateNotFound); ok {
		return
	}
	if cb.Logger != nil {
		cb.Logger.Errorf("Error from: %v (%v) duration: %v. %v", name, id, end.Sub(start), err)
	}
}

func FlowMessageToString(fmsg *flowmessage.FlowMessage) string {
	srcmac := make([]byte, 8)
	dstmac := make([]byte, 8)
	binary.BigEndian.PutUint64(srcmac, fmsg.SrcMac)
	binary.BigEndian.PutUint64(dstmac, fmsg.DstMac)
	srcmac = srcmac[2:8]
	dstmac = dstmac[2:8]

	s := fmt.Sprintf("Type:%v TimeReceived:%v SequenceNum:%v SamplingRate:%v "+
		"SamplerAddress:%v TimeFlowStart:%v TimeFlowEnd:%v Bytes:%v Packets:%v SrcAddr:%v "+
		"DstAddr:%v Etype:%v Proto:%v SrcPort:%v DstPort:%v SrcIf:%v DstIf:%v SrcMac:%v "+
		"DstMac:%v SrcVlan:%v DstVlan:%v VlanId:%v IngressVrfID:%v EgressVrfID:%v IPTos:%v "+
		"ForwardingStatus:%v IPTTL:%v TCPFlags:%v IcmpType:%v IcmpCode:%v IPv6FlowLabel:%v "+
		"FragmentId:%v FragmentOffset:%v BiFlowDirection:%v SrcAS:%v DstAS:%v NextHop:%v NextHopAS:%v SrcNet:%v DstNet:%v",
		fmsg.Type, fmsg.TimeReceived, fmsg.SequenceNum, fmsg.SamplingRate, net.IP(fmsg.SamplerAddress),
		fmsg.TimeFlowStart, fmsg.TimeFlowEnd, fmsg.Bytes, fmsg.Packets, net.IP(fmsg.SrcAddr), net.IP(fmsg.DstAddr),
		fmsg.Etype, fmsg.Proto, fmsg.SrcPort, fmsg.DstPort, fmsg.SrcIf, fmsg.DstIf, net.HardwareAddr(srcmac),
		net.HardwareAddr(dstmac), fmsg.SrcVlan, fmsg.DstVlan, fmsg.VlanId, fmsg.IngressVrfID,
		fmsg.EgressVrfID, fmsg.IPTos, fmsg.ForwardingStatus, fmsg.IPTTL, fmsg.TCPFlags, fmsg.IcmpType,
		fmsg.IcmpCode, fmsg.IPv6FlowLabel, fmsg.FragmentId, fmsg.FragmentOffset, fmsg.BiFlowDirection, fmsg.SrcAS, fmsg.DstAS,
		net.IP(fmsg.NextHop), fmsg.NextHopAS, fmsg.SrcNet, fmsg.DstNet)
	return s
}

func FlowMessageToJSON(fmsg *flowmessage.FlowMessage) string {
	srcmac := make([]byte, 8)
	dstmac := make([]byte, 8)
	binary.BigEndian.PutUint64(srcmac, fmsg.SrcMac)
	binary.BigEndian.PutUint64(dstmac, fmsg.DstMac)
	srcmac = srcmac[2:8]
	dstmac = dstmac[2:8]

	s := fmt.Sprintf("{\"Type\":\"%v\",\"TimeReceived\":%v,\"SequenceNum\":%v,\"SamplingRate\":%v,"+
		"\"SamplerAddress\":\"%v\",\"TimeFlowStart\":%v,\"TimeFlowEnd\":%v,\"Bytes\":%v,\"Packets\":%v,\"SrcAddr\":\"%v\","+
		"\"DstAddr\":\"%v\",\"Etype\":%v,\"Proto\":%v,\"SrcPort\":%v,\"DstPort\":%v,\"SrcIf\":%v,\"DstIf\":%v,\"SrcMac\":\"%v\","+
		"\"DstMac\":\"%v\",\"SrcVlan\":%v,\"DstVlan\":%v,\"VlanId\":%v,\"IngressVrfID\":%v,\"EgressVrfID\":%v,\"IPTos\":%v,"+
		"\"ForwardingStatus\":%v,\"IPTTL\":%v,\"TCPFlags\":%v,\"IcmpType\":%v,\"IcmpCode\":%v,\"IPv6FlowLabel\":%v,"+
		"\"FragmentId\":%v,\"FragmentOffset\":%v,\"BiFlowDirection\":%v,\"SrcAS\":%v,\"DstAS\":%v,\"NextHop\":\"%v\",\"NextHopAS\":%v,\"SrcNet\":%v,\"DstNet\":%v}",
		fmsg.Type, fmsg.TimeReceived, fmsg.SequenceNum, fmsg.SamplingRate, net.IP(fmsg.SamplerAddress),
		fmsg.TimeFlowStart, fmsg.TimeFlowEnd, fmsg.Bytes, fmsg.Packets, net.IP(fmsg.SrcAddr), net.IP(fmsg.DstAddr),
		fmsg.Etype, fmsg.Proto, fmsg.SrcPort, fmsg.DstPort, fmsg.SrcIf, fmsg.DstIf, net.HardwareAddr(srcmac),
		net.HardwareAddr(dstmac), fmsg.SrcVlan, fmsg.DstVlan, fmsg.VlanId, fmsg.IngressVrfID,
		fmsg.EgressVrfID, fmsg.IPTos, fmsg.ForwardingStatus, fmsg.IPTTL, fmsg.TCPFlags, fmsg.IcmpType,
		fmsg.IcmpCode, fmsg.IPv6FlowLabel, fmsg.FragmentId, fmsg.FragmentOffset, fmsg.BiFlowDirection, fmsg.SrcAS, fmsg.DstAS,
		net.IP(fmsg.NextHop), fmsg.NextHopAS, fmsg.SrcNet, fmsg.DstNet)
	return s
}

func UDPRoutine(name string, decodeFunc decoder.DecoderFunc, workers int, addr string, port int, sockReuse bool, logger Logger) error {
	ecb := DefaultErrorCallback{
		Logger: logger,
	}

	decoderParams := decoder.DecoderParams{
		DecoderFunc:   decodeFunc,
		DoneCallback:  DefaultAccountCallback,
		ErrorCallback: ecb.Callback,
	}

	processor := decoder.CreateProcessor(workers, decoderParams, name)
	processor.Start()

	addrUDP := net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: port,
	}

	var udpconn *net.UDPConn
	var err error

	if sockReuse {
		pconn, err := reuseport.ListenPacket("udp", addrUDP.String())
		defer pconn.Close()
		if err != nil {
			return err
		}
		var ok bool
		udpconn, ok = pconn.(*net.UDPConn)
		if !ok {
			return err
		}
	} else {
		udpconn, err = net.ListenUDP("udp", &addrUDP)
		defer udpconn.Close()
		if err != nil {
			return err
		}
	}

	payload := make([]byte, 9000)

	localIP := addrUDP.IP.String()
	if addrUDP.IP == nil {
		localIP = ""
	}

	for {
		size, pktAddr, _ := udpconn.ReadFromUDP(payload)
		payloadCut := make([]byte, size)
		copy(payloadCut, payload[0:size])

		baseMessage := BaseMessage{
			Src:     pktAddr.IP,
			Port:    pktAddr.Port,
			Payload: payloadCut,
		}
		processor.ProcessMessage(baseMessage)

		MetricTrafficBytes.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Add(float64(size))
		MetricTrafficPackets.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Inc()
		MetricPacketSizeSum.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Observe(float64(size))
	}
}
