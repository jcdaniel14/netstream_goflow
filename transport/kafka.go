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
	"pe1huaweiprueba1:10": "Gi0/3/4",
}

//Exporter Map
var nodes = map[string]string{
	"200.93.195.22": "pe1huaweiprueba1",
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
