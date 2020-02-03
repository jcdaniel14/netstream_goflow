package transport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	flowmessage "github.com/cloudflare/goflow/pb"
	"github.com/cloudflare/goflow/utils"
	"net"
	"strconv"
	"time"

	//"github.com/golang/protobuf/descriptor"
	"errors"
	"flag"
	sarama "github.com/Shopify/sarama"
	"os"
	"reflect"
	"strings"
)

var (
	KafkaTLS   *bool
	KafkaSASL  *bool
	KafkaTopic *string
	KafkaSrv   *string
	KafkaBrk   *string

	KafkaLogErrors *bool

	KafkaHashing *bool
	KafkaKeying  *string
)

//SNMP Map --- Put here console output
var interfaces = map[string]string{
	"rointernetgye4:170": "TenGigE0/6/0/11",
	"rointernetgye4:232": "Bundle-Ether98",
	"rointernetgye4:188": "Bundle-Ether100",
	"rointernetgye4:216": "Bundle-Ether96",
	"rointernetgye4:211": "Bundle-Ether99",
	"rointernetgye4:183": "Bundle-Ether95",
	"rointernetgye4:228": "Bundle-Ether97",
	"rointernetgye4:22":  "TenGigE0/0/0/2",
	"rointernetgye4:137": "TenGigE0/2/0/11",
	"rointernetgye4:138": "TenGigE0/2/0/12",
	"rointernetgye4:171": "TenGigE0/6/0/12",
	"rointernetgye4:127": "TenGigE0/2/0/1",
	"rointernetgye4:233": "Bundle-Ether93",

	"rointernetgye3:143": "Bundle-Ether250",
	"rointernetgye3:134": "Bundle-Ether98",
	"rointernetgye3:120": "Bundle-Ether200",
	"rointernetgye3:38":  "TenGigE0/2/0/10",

	"routercdn2uio:274": "Bundle-Ether80",
	"routercdn2uio:249": "Bundle-Ether112",
	"routercdn2uio:256": "BVI2300",
	"routercdn2uio:243": "BVI2201",
	"routercdn2uio:283": "BVI2301",
	"routercdn2uio:268": "Bundle-Ether114.2100",
	"routercdn2uio:269": "BVI2202",
	"routercdn2uio:265": "Bundle-Ether30",
	"routercdn2uio:267": "Bundle-Ether114",

	"routercdn2gye:306": "Bundle-Ether100",
	"routercdn2gye:294": "BVI2300",
	"routercdn2gye:274": "BVI2201",
	"routercdn2gye:318": "BVI2301",
	"routercdn2gye:312": "Bundle-Ether107.2100",
	"routercdn2gye:307": "Bundle-Ether104",
	"routercdn2gye:126": "TenGigE0/4/0/1",
	"routercdn2gye:276": "Bundle-Ether108",
	"routercdn2gye:305": "Bundle-Ether30",
	"routercdn2gye:311": "Bundle-Ether107",

	"rointernetuio1:91":  "Bundle-Ether100",
	"rointernetuio1:109": "Bundle-Ether93",
	"rointernetuio1:92":  "Bundle-Ether200",
	"rointernetuio1:119": "TenGigE0/3/0/1",
	"rointernetuio1:107": "Bundle-Ether90",
	"rointernetuio1:65":  "TenGigE0/7/0/3",
	"rointernetuio1:50":  "TenGigE0/6/0/4",
}

//Exporter Map
var nodes = map[string]string{
	"10.101.11.211":  "rointernetgye4",
	"10.101.11.210":  "rointernetgye3",
	"201.218.56.129": "routercdn2gye",
	"10.101.21.149":  "rointernetuio1",
	"10.101.21.148":  "routercdn2uio",
}

type KafkaState struct {
	producer sarama.AsyncProducer
	topic    string
	hashing  bool
	keying   []string
}

type Flow struct {
	Exporter string `json:"exporter"`
	//FlowStart string `json:"first_switched"`
	FlowEnd string `json:"last_switched"`
	Bytes   uint64 `json:"bytes"`
	//Packets   uint64 `json:"packets"`
	SrcAddr   string `json:"src_addr"`
	DstAddr   string `json:"dst_addr"`
	Protocol  uint32 `json:"protocol"`
	IPVersion string `json:"ip_version"`
	SrcPort   uint32 `json:"src_port"`
	DstPort   uint32 `json:"dst_port"`
	IfName    string `json:"input_ifname"`
	//SrcMask   uint32 `json:"src_mask"`
	//DstMask   uint32 `json:"dst_mask"`
	Gate string `json:"gate"`
}

func RegisterFlags() {
	KafkaTLS = flag.Bool("kafka.tls", false, "Use TLS to connect to Kafka")
	KafkaSASL = flag.Bool("kafka.sasl", false, "Use SASL/PLAIN data to connect to Kafka (TLS is recommended and the environment variables KAFKA_SASL_USER and KAFKA_SASL_PASS need to be set)")
	KafkaTopic = flag.String("kafka.topic", "flow-messages", "Kafka topic to produce to")
	KafkaSrv = flag.String("kafka.srv", "", "SRV record containing a list of Kafka brokers (or use kafka.out.brokers)")
	KafkaBrk = flag.String("kafka.brokers", "127.0.0.1:9092,[::1]:9092", "Kafka brokers list separated by commas")

	KafkaLogErrors = flag.Bool("kafka.log.err", false, "Log Kafka errors")

	KafkaHashing = flag.Bool("kafka.hashing", false, "Enable partitioning by hash instead of random")
	KafkaKeying = flag.String("kafka.key", "SamplerAddr,DstAS", "Kafka list of fields to do hashing on (partition) separated by commas")
}

func StartKafkaProducerFromArgs(log utils.Logger) (*KafkaState, error) {
	addrs := make([]string, 0)
	if *KafkaSrv != "" {
		addrs, _ = utils.GetServiceAddresses(*KafkaSrv)
	} else {
		addrs = strings.Split(*KafkaBrk, ",")
	}
	return StartKafkaProducer(addrs, *KafkaTopic, *KafkaHashing, *KafkaKeying, *KafkaTLS, *KafkaSASL, *KafkaLogErrors, log)
}

func StartKafkaProducer(addrs []string, topic string, hashing bool, keying string, useTls bool, useSasl bool, logErrors bool, log utils.Logger) (*KafkaState, error) {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Producer.Return.Successes = false
	kafkaConfig.Producer.Return.Errors = logErrors
	if useTls {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error initializing TLS: %v", err))
		}
		kafkaConfig.Net.TLS.Enable = true
		kafkaConfig.Net.TLS.Config = &tls.Config{RootCAs: rootCAs}
	}

	var keyingSplit []string
	if hashing {
		kafkaConfig.Producer.Partitioner = sarama.NewHashPartitioner
		keyingSplit = strings.Split(keying, ",")
	}

	if useSasl {
		if !useTls && log != nil {
			log.Warn("Using SASL without TLS will transmit the authentication in plaintext!")
		}
		kafkaConfig.Net.SASL.Enable = true
		kafkaConfig.Net.SASL.User = os.Getenv("KAFKA_SASL_USER")
		kafkaConfig.Net.SASL.Password = os.Getenv("KAFKA_SASL_PASS")
		if kafkaConfig.Net.SASL.User == "" && kafkaConfig.Net.SASL.Password == "" {
			return nil, errors.New("Kafka SASL config from environment was unsuccessful. KAFKA_SASL_USER and KAFKA_SASL_PASS need to be set.")
		} else if log != nil {
			log.Infof("Authenticating as user '%s'...", kafkaConfig.Net.SASL.User)
		}
	}

	kafkaProducer, err := sarama.NewAsyncProducer(addrs, kafkaConfig)
	if err != nil {
		return nil, err
	}
	state := KafkaState{
		producer: kafkaProducer,
		topic:    topic,
		hashing:  hashing,
		keying:   keyingSplit,
	}

	if logErrors {
		go func() {
			for {
				select {
				case msg := <-kafkaProducer.Errors():
					if log != nil {
						log.Error(msg)
					}
				}
			}
		}()
	}

	return &state, nil
}

func HashProto(fields []string, flowMessage *flowmessage.FlowMessage) string {
	var keyStr string

	if flowMessage != nil {
		vfm := reflect.ValueOf(flowMessage)
		vfm = reflect.Indirect(vfm)

		for _, kf := range fields {
			fieldValue := vfm.FieldByName(kf)
			if fieldValue.IsValid() {
				keyStr += fmt.Sprintf("%v-", fieldValue)
			}
		}
	}

	return keyStr
}

func (s KafkaState) SendKafkaFlowMessage(flowMessage *flowmessage.FlowMessage) {
	var key sarama.Encoder
	if s.hashing {
		keyStr := HashProto(s.keying, flowMessage)
		key = sarama.StringEncoder(keyStr)
	}
	// ==================== PARSING WITH JSON INSTEAD OF PROTOBUF AND CONVERSION OF IP (BYTES) TO STRING
	flowGS := parseFlow(flowMessage)
	b, _ := json.Marshal(flowGS)
	//reqString := string(b)
	//fmt.Println("Format --> ", reqString)
	//b, _ := proto.Marshal(flowMessage)
	s.producer.Input() <- &sarama.ProducerMessage{
		Topic: s.topic,
		Key:   key,
		Value: sarama.ByteEncoder(b),
	}
}

func parseFlow(f *flowmessage.FlowMessage) interface{} {
	//Dictionary mapping
	export := net.IP(f.SamplerAddress).String()
	n := nodes[export]
	srcIf := interfaces[n+":"+strconv.Itoa(int(f.SrcIf))]
	if len(srcIf) == 0 {
		srcIf = strconv.Itoa(int(f.SrcIf))
	}

	rate := uint64(1000)
	ipVersion := ""
	//flowStart := f.TimeFlowStart
	flowEnd := f.TimeFlowEnd
	srcAddr := net.IP(f.SrcAddr).String()

	if strings.Contains(srcAddr, ":") {
		ipVersion = "IPv6"
	} else {
		ipVersion = "IPv4"
	}

	//============== Resolve Mask 0 Bug
	srcMask := f.SrcNet
	dstMask := f.DstNet
	if srcMask == 0 {
		srcMask = 32
	}
	if dstMask == 0 {
		dstMask = 32
	}
	//============== END

	//Gate
	Gate := n + ":" + srcIf

	//firstSw := time.Unix(int64(flowStart), 0).UTC().Format("2006-01-02T15:04:05.000")
	lastSw := time.Unix(int64(flowEnd), 0).UTC().Format("2006-01-02T15:04:05.000")
	flow := Flow{
		Exporter: n,
		//FlowStart: firstSw,
		FlowEnd: lastSw,
		Bytes:   f.Bytes * rate,
		//Packets:   f.Packets * rate,
		SrcAddr:   srcAddr,
		DstAddr:   net.IP(f.DstAddr).String(),
		Protocol:  f.Proto,
		IPVersion: ipVersion,
		SrcPort:   f.SrcPort,
		DstPort:   f.DstPort,
		IfName:    srcIf,
		Gate:      Gate,
	}
	//SrcMask:   srcMask,
	//DstMask:   dstMask}
	return flow
}

func (s KafkaState) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		s.SendKafkaFlowMessage(msg)
	}
}
