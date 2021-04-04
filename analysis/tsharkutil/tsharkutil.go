package tsharkutil

import (
	"bytes"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

//const TsharkPath = "/usr/local/bin/tshark"

const TsharkPath = "/usr/local/bin/tshark"

type PckInfo struct {
	StreamId   int
	FrameNo    int
	Ts         float64
	SrcIp      string
	DstIp      string
	SrcPort    int
	DstPort    int
	IpLen      int
	TcpLen     int
	Win        int
	TCPRetrans bool
	TCPLost    bool
	TCPReOrder bool
	Seq        uint
	Ack        uint
	Flag       string
	IsAck      bool
	IsRst      bool
	IsPsh      bool
	IsSyn      bool
}

type PckSSLInfo struct {
	PckInfo
	SSLRecordType   int
	SSL_client_ip   string
	SSL_clientstate int
	SSL_serverstate int
	Claimed         bool
}

type TCPFlow struct {
	SrcIp   string
	DstIp   string
	SrcPort string
	DstPort string
}

type HRequest struct {
	FrameNum int
	Ts       float64
	Method   string
	Uri      string
	FrameEnd int
}

type HResponse struct {
	FrameNum int
	Ts       float64
	Code     int
	FrameEnd int
	FrameLen int
}

type StreamInfo struct {
	StreamId int
	Request  []HRequest
	Response []HResponse
}

type StreamMap struct {
	StreamId int
	ReqIdx   int
}

type StreamPcap struct {
	StreamId int
	Request  *HRequest
	Response *HResponse
	PckDump  []*PckInfo
}

type StreamProgress struct {
	StreamId    int
	PckIndex    int
	OngoingResp string
}

type PcapThroughput struct {
	Slot      float64
	STs       float64
	ETs       float64
	ByteTotal int
	Tput      float64
}

type StreamSSLInfo struct {
	Clientstate int
	Serverstate int
	Clientip    string
}

type HS_PckInfo struct {
	StreamId   int
	PacketId   int
	PacketTime float64
	SrcIp      string
	DstIp      string
	Proto      string
	PacketLen  int
	SrcPort    int
	DstPort    int
	//PacketInfo string
}

type HS_Request struct {
	FrameNum int
	Ts       float64
	Method   string
	Uri      string
}

type HS_Response struct {
	FrameNum int
	Ts       float64
	FrameEnd int
}

type HS_StreamInfo struct {
	StreamId  int
	Request   []HRequest
	Response  []HResponse
	Downup    bool
	StreamLen uint
}

// add the struct of rtt_stream to record the list of rtt in each testing streams
type Rtt struct {
	TSend float64
	TAck  float64
	TRtt  float64
}

type RTT_Stream struct {
	//StreamId int
	TStart        float64
	TEnd          float64
	Rtts          []Rtt
	TFirstRetrans float64
	Downup        bool
}

type Lost_Packet struct {
	Time           float64
	SequenceNumber uint
	Length         int
	Islost         bool
}

type LostStream struct {
	TStart         float64
	TEnd           float64
	Pck_FromHost   []*Lost_Packet
	Pck_FromServer []*Lost_Packet
	Downup         bool
	HostPort       int
	ServerPort     int
}

const HttpPort = "8080,6020-6022"

func DNSQueryTime(nameprefix, host string) (float64, string) {
	//accept both full path to pcap or partial path without .pcap
	pfilename := getpcappath(nameprefix)
	dnsfilter := `dns.qry.name contains ` + host + ` && dns.flags==0x0100`
	log.Println(pfilename)
	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-E", `separator=,`,
		"-Tfields",
		"-e", "frame.time_epoch",
		"-e", "ip.src", "-Y", dnsfilter)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		if len(out.String()) > 2 {
			lines := strings.Split(out.String(), "\n")
			d := strings.Split(lines[0], ",")
			unixts, err := strconv.ParseFloat(string(d[0]), 64)
			if err != nil {
				log.Fatal("DNSQueryTime:", nameprefix, err)
			}
			return unixts, strings.TrimSpace(d[1])
		} else {
			//run successfully, but no dns query match
			return 0, ""

		}
	} else {
		log.Println(out.String())
		log.Println(stderr.String())
		log.Fatal(err)
		return 0, ""
	}
}

func DNSHostIP(nameprefix string, hostnamemap map[string]string) {
	//empty map, do nothing
	if len(hostnamemap) == 0 {
		return
	}
	pfilename := getpcappath(nameprefix)
	dnsfilter := `dns.resp.name contains nflxvideo.net`
	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-E", `separator=,`,
		"-Tfields",
		"-e", "dns.qry.name",
		"-e", "dns.a",
		"-Y", dnsfilter)
	var out, stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		lines := strings.Split(out.String(), "\n")
		if len(lines) > 0 {
			for _, ln := range lines {
				if len(ln) > 1 {
					d := strings.Split(ln, ",")
					//have answers
					if len(d) == 2 {
						hostnamemap[d[0]] = d[1]
					}
				}
			}
			//done matching using pcap, check for hostname that is still empty, resolve now
			for hname, ipstr := range hostnamemap {
				//still no IP
				if len(ipstr) == 0 {
					addrs, err := net.LookupIP(hname)
					if err == nil {
						hostnamemap[hname] = addrs[0].String()
					}
				}
			}
		}
	} else {
		log.Println(out.String())
		log.Println(stderr.String())
		log.Fatal(err)
		return
	}
}

//use only when the pcap does not contain the DNS query we want
func HTTPSSyncTime(nameprefix string) float64 {
	pfilename := getpcappath(nameprefix)
	//SYN and HTTPS
	synfilter := `tcp.flags==0x002 && tcp.dstport==443`
	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-E", `separator=,`,
		"-Tfields",
		"-e", "frame.time_epoch",
		"-e", "ip.src", "-Y", synfilter)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		lines := strings.Split(out.String(), "\n")
		if len(lines) > 0 {
			//only consider the first syn
			d := strings.Split(lines[0], ",")
			if len(d[0]) > 9 {
				unixts, err := strconv.ParseFloat(string(d[0]), 64)
				if err != nil {
					log.Fatal("HTTPSync:", nameprefix, err)
				}
				return unixts
			}
		}
		//run successfully, but no syn match
		return 0
	} else {
		log.Println(out.String())
		log.Println(stderr.String())
		log.Fatal(err)
		return 0
	}

}

func HTTPRequestStream(nameprefix string, clues []string) (map[int]*StreamInfo, map[string][]*StreamMap) {
	pfilename := getpcappath(nameprefix)
	keyfilename := Getkeypath(nameprefix)
	//	httpfilter := `http.request.uri contains "` + uriclues + `"`
	clueprefix := []string{}
	for _, clue := range clues {
		cluefilter := `http.request.uri contains "` + clue + `"`
		clueprefix = append(clueprefix, cluefilter)
	}
	urifilter := `(` + strings.Join(clueprefix, " || ") + `)`
	//OPTIONS is not regarded as request in wireshark. hardcode a case here
	httpfilter := `(http.request || http.request.method==OPTIONS) && ` + urifilter + ``
	var out bytes.Buffer
	var stderr bytes.Buffer
	var cmd *exec.Cmd
	if len(keyfilename) > 0 {
		log.Println("Run cmd with key")
		cmd = exec.Command(TsharkPath, "-nr", pfilename,
			"-E", `separator=;`,
			"-o", "ssl.keylog_file:"+keyfilename,
			//"-d", "tcp.port==6020-8080,ssl",
			"-o", "http.ssl.port:6020-8080",
			"-Tfields",
			"-e", "tcp.stream",
			"-e", "http.request.uri",
			"-Y", httpfilter)
	} else {
		cmd = exec.Command(TsharkPath, "-nr", pfilename,
			"-E", `separator=";"`,
			"-Tfields",
			"-e", "tcp.stream",
			"-e", "http.request.uri",
			"-Y", httpfilter)
	}
	log.Println("HTTPRequestStream command: ",cmd)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		lines := strings.Split(out.String(), "\n")
		streammap := make(map[int]bool)
		streamids := []int{}
		//streams := []StreamInfo{}
		//		log.Println("newlen:", len(streams))
		for _, ln := range lines {
			if len(ln) > 1 {
				flow := strings.Split(ln, ";")
				stmid, _ := strconv.Atoi(flow[0])
				if !streammap[stmid] {
					//new stream, we only need unique stream here
					streamids = append(streamids, stmid)
				}
			}
		}
		//		log.Println("streamids", streamids)
		return GetHTTPfromStreams(nameprefix, streamids)
	} else {
		log.Println(out.String())
		log.Println(stderr.String())
		log.Fatal(err)
		//wont get here anyway
		return nil, nil
	}
}

//get all packets to/from measurement servers
//ssl.handshake flag cannot correctly indicate client hello. use record type 22 and 23 to distinguish

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func GetSSLStreamsfromIPs(nameprefix string, hostnameipmap map[string]string, hostports []string) ([]*PckSSLInfo, map[int]*RTT_Stream, map[int]*LostStream) {
	pfilename := getpcappath(nameprefix)
	ips := []string{}
	for _, ip := range hostnameipmap {
		if len(ip) > 1 {
			ips = append(ips, `ip.host==`+ip)
		}
	}
	ipfilters := `(` + strings.Join(ips, " || ") + `)`
	log.Println("ip list = ", ipfilters)

	var portfilters string
	if len(hostports) > 1 {
		len := strconv.Itoa(len(hostports))
		portfilters = `tcp.port==` + hostports[0] + ":" + len + `,ssl`
	} else {
		portfilters = `tcp.port==` + hostports[0] + `,ssl`
	}

	//
	//for _, port := range hostports{
	//	if len(port) > 1 && !contains(ports, `tcp.port==` + port){
	//		ports = append(ports, `tcp.port==`+port)
	//	}
	//}
	//portfilters := strings.Join(ports, " || ") + `,ssl`
	log.Println("port list = ", portfilters)

	//tc_port := `tcp.port==` + port_num + ` ,ssl`
	//ssl content type use , for separator if there are multiple SSL layer. we change to use | instead
	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-d", portfilters,
		"-E", `separator=|`,
		"-Tfields",
		"-e", "tcp.stream",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "ip.len",
		"-e", "tcp.len",
		"-e", "tcp.window_size",
		"-e", "tcp.analysis.retransmission",
		"-e", "tcp.analysis.lost_segment",
		"-e", "tcp.analysis.out_of_order",
		"-e", "tcp.seq",
		"-e", "tcp.ack",
		"-e", "tcp.flags",
		"-e", "ssl.record.content_type",
		"-e", "ssl.record.opaque_type",
		"-e", "ssl.record.version",
		"-e", "ssl.record.length",
		// insert tcp.flags.ack, if 0, ack packets
		"-e", "tcp.flags.ack",
		"-e", "tcp.flags.reset",
		"-e", "tcp.flags.push",
		"-e", "tcp.flags.syn",
		"-e", "tcp.analysis.fast_retransmission",
		"-Y", ipfilters)
	log.Println(cmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	log.Println("ssl stream error happend?")
	err := cmd.Run()
	if err == nil {
		log.Println("did not happen")
		allpck := ParseSSLPckfromTshark(out.String())
		return allpck, GetSSLRtt(allpck), GetSSLPckLost(allpck)
	} else {
		log.Println(stderr.String())
		log.Fatal(err)
		return nil, nil, nil
	}

}

// get rtt list for each stream
func GetRtt(PacketTraces []*PckInfo) map[int]*RTT_Stream {
	sents := make(map[int][]*PckInfo)
	acks := make(map[int][]*PckInfo)
	rtts := make(map[int]*RTT_Stream)
	tretrans := make(map[int]float64)
	LocalIp_sub := "192.172.226"
	var LocalIp string
	//find the local ip address
	//only for ookla
	//for _, pck := range PacketTraces{
	//	if pck.SrcPort == 443 || pck.SrcPort == 8080{
	//		LocalIp = pck.DstIp
	//		break
	//	}else if pck.DstPort == 443 || pck.DstPort == 8080{
	//		LocalIp = pck.SrcIp
	//		break
	//	}
	//}
	for _, pck := range PacketTraces {
		if strings.Contains(pck.SrcIp, LocalIp_sub) {
			LocalIp = pck.SrcIp
			break
		} else if strings.Contains(pck.DstIp, LocalIp_sub) {
			LocalIp = pck.DstIp
			break
		}
	}
	// gather ack packet for each flow
	for _, pck := range PacketTraces {

		//filter out retranmission || fast_retranmission packets
		if pck.TCPRetrans == true {
			if _, ok := tretrans[pck.StreamId]; !ok {
				tretrans[pck.StreamId] = pck.Ts
			}
		}
		if pck.IsAck == true && pck.DstIp == LocalIp {
			acks[pck.StreamId] = append(acks[pck.StreamId], pck)
			// is a ack packet
		} else if pck.IsRst == false && pck.SrcIp == LocalIp && ((!pck.IsAck) || pck.IsPsh || pck.IsSyn) {
			sents[pck.StreamId] = append(sents[pck.StreamId], pck)
			// is a non-ack packet sent from localhost to the server
		}
	}
	//calculate rtt for each packet sent from the localhost
	for StreamId, list := range sents {
		var tmp_rtt_list []Rtt

		for _, SentPck := range list {
			sum := SentPck.Seq + uint(SentPck.TcpLen)
			for _, Ackpck := range acks[StreamId] {
				//sum==0 && Ackpck.Ack==1 ->syn packets
				if (Ackpck.Ack == sum || (sum == 0 && Ackpck.Ack == 1)) && Ackpck.FrameNo > SentPck.FrameNo {
					//find the ack packet for this sent packet
					//log.Println("find match",SentPck.FrameNo,Ackpck.FrameNo)
					tmp_rtt := Rtt{TSend: SentPck.Ts, TAck: Ackpck.Ts, TRtt: Ackpck.Ts - SentPck.Ts}
					tmp_rtt_list = append(tmp_rtt_list, tmp_rtt)
				}

			}
		}
		tmp_rtt_stream := RTT_Stream{tmp_rtt_list[0].TSend, tmp_rtt_list[len(tmp_rtt_list)-1].TAck, tmp_rtt_list, tretrans[StreamId], false}
		rtts[StreamId] = &tmp_rtt_stream
	}
	//for _,r := range rtts{
	//	log.Println("rtt list", *r)
	//}
	return rtts
}

func GetSSLRtt(PacketTraces []*PckSSLInfo) map[int]*RTT_Stream {
	sents := make(map[int][]*PckSSLInfo)
	acks := make(map[int][]*PckSSLInfo)
	rtts := make(map[int]*RTT_Stream)
	tretrans := make(map[int]float64)
	//LocalIp_sub := "192.172.226"
	//var LocalIp string

	//for _, pck := range PacketTraces {
	//	if strings.Contains(pck.SrcIp, LocalIp_sub) {
	//		LocalIp = pck.SrcIp
	//		break
	//	} else if strings.Contains(pck.DstIp, LocalIp_sub) {
	//		LocalIp = pck.DstIp
	//		break
	//	}
	//}
	// gather ack packet for each flow
	for _, pck := range PacketTraces {
		//filter out retranmission || fast_retranmission packets
		if pck.TCPRetrans == true {
			if _, ok := tretrans[pck.StreamId]; !ok {
				tretrans[pck.StreamId] = pck.Ts
			}
		}
		if pck.IsAck == true && pck.DstIp == pck.SSL_client_ip {
			acks[pck.StreamId] = append(acks[pck.StreamId], pck)
			// is a ack packet
			//}else if pck.IsAck==false && pck.IsRst==false && pck.SrcIp == LocalIp{
		} else if pck.IsRst == false && pck.SrcIp == pck.SSL_client_ip && ((!pck.IsAck) || pck.IsPsh || pck.IsSyn) {
			sents[pck.StreamId] = append(sents[pck.StreamId], pck)
			// is a non-pure-ack packet sent from localhost to the server
		}
	}
	//calculate rtt for each packet sent from the localhost
	for StreamId, list := range sents {
		var tmp_rtt_list []Rtt

		for _, SentPck := range list {
			sum := SentPck.Seq + uint(SentPck.TcpLen)
			for _, Ackpck := range acks[StreamId] {
				//sum==0 && Ackpck.Ack==1 ->syn packets
				if (Ackpck.Ack == sum || (sum == 0 && Ackpck.Ack == 1)) && Ackpck.FrameNo > SentPck.FrameNo {
					//find the ack packet for this sent packet
					//log.Println("find match:","sent_frame_no: ",SentPck.FrameNo, "send_sum:",sum,"ack_frame_no",Ackpck.FrameNo,"ack_num",Ackpck.Ack)
					tmp_rtt := Rtt{TSend: SentPck.Ts, TAck: Ackpck.Ts, TRtt: Ackpck.Ts - SentPck.Ts}
					tmp_rtt_list = append(tmp_rtt_list, tmp_rtt)
					break
				}

			}
		}

		tmp_rtt_stream := RTT_Stream{tmp_rtt_list[0].TSend, tmp_rtt_list[len(tmp_rtt_list)-1].TAck, tmp_rtt_list, tretrans[StreamId], false}
		rtts[StreamId] = &tmp_rtt_stream
	}
	//log.Println("localhost:",LocalIp)
	//for _,r := range rtts{
	//	log.Println("rtt list", *r)
	//}
	return rtts
}

// plot packet lost time series
func GetSSLPckLost(PacketTraces []*PckSSLInfo) map[int]*LostStream {
	snt := make(map[int][]*Lost_Packet)
	rcv := make(map[int][]*Lost_Packet)
	stream_list := make(map[int][]int)

	// return list
	Lost_streams := make(map[int]*LostStream)

	//allpcks := make(map[int][]*Lost_Packet)
	//LocalIp_sub := "192.172.226"
	//var LocalIp string
	// for now, only return packets sent from the server

	//lost_episode := make(map[int][]int)
	//snt_reorder := make(map[int][]*PckSSLInfo)
	//rcv_reorder := make(map[int][]*PckSSLInfo)

	//for _, pck := range PacketTraces {
	//	if strings.Contains(pck.SrcIp, LocalIp_sub) {
	//		LocalIp = pck.SrcIp
	//		break
	//	} else if strings.Contains(pck.DstIp, LocalIp_sub) {
	//		LocalIp = pck.DstIp
	//		break
	//	}
	//}
	// find the local ip address

	// inferring packet Lost according to packet retrans & fast retrans.
	// downloading flows --> only calculate lost packets from the server;
	// uploading flows --> only calculate lost packets from the host; (which should be rarer?)
	// problem is that there is a delay between packet retrans & changing congestion window size....
	// which might affect the packet Lost pattern because the rtt of different flows are different
	// (will look into it later,currently thinking of the feasibility of adding rtt into the methodology..)
	for _, pck := range PacketTraces {
		// get src & dst ports
		if _, ok := stream_list[pck.StreamId]; !ok {
			if pck.SrcIp == pck.SSL_client_ip {
				stream_list[pck.StreamId] = append(stream_list[pck.StreamId], pck.SrcPort, pck.DstPort)
			} else {
				stream_list[pck.StreamId] = append(stream_list[pck.StreamId], pck.DstPort, pck.SrcPort)
			}
		}

		if pck.TcpLen != 0 || !pck.IsAck || pck.IsPsh || pck.IsSyn {
			//not ack
			if pck.DstIp == pck.SSL_client_ip {
				if pck.TCPRetrans == true {
					tmp_pck := &Lost_Packet{Time: pck.Ts, Length: pck.TcpLen, SequenceNumber: pck.Seq, Islost: true}
					rcv[pck.StreamId] = append(rcv[pck.StreamId], tmp_pck)
				} else {
					tmp_pck := &Lost_Packet{Time: pck.Ts, Length: pck.TcpLen, SequenceNumber: pck.Seq, Islost: false}
					rcv[pck.StreamId] = append(rcv[pck.StreamId], tmp_pck)
				}
			} else if pck.SrcIp == pck.SSL_client_ip {
				if pck.TCPRetrans == true {
					tmp_pck := &Lost_Packet{Time: pck.Ts, Length: pck.TcpLen, SequenceNumber: pck.Seq, Islost: true}
					snt[pck.StreamId] = append(rcv[pck.StreamId], tmp_pck)
				} else {
					tmp_pck := &Lost_Packet{Time: pck.Ts, Length: pck.TcpLen, SequenceNumber: pck.Seq, Islost: false}
					snt[pck.StreamId] = append(rcv[pck.StreamId], tmp_pck)
				}

			}
		}
	}
	for stream_id, ports := range stream_list {
		Lost_streams[stream_id] = &LostStream{TStart: -1.0, TEnd: -1.0, Pck_FromHost: snt[stream_id], Pck_FromServer: rcv[stream_id], Downup: false, HostPort: ports[0], ServerPort: ports[1]}
	}
	return Lost_streams
}

// plot packet lost time series
func GetPckLost(PacketTraces []*PckInfo) map[int]*LostStream {
	snt := make(map[int][]*Lost_Packet)
	rcv := make(map[int][]*Lost_Packet)
	stream_list := make(map[int][]int)

	// return list
	Lost_streams := make(map[int]*LostStream)

	//allpcks := make(map[int][]*Lost_Packet)
	LocalIp_sub := "192.172.226"
	var LocalIp string
	// for now, only return packets sent from the server

	//lost_episode := make(map[int][]int)
	//snt_reorder := make(map[int][]*PckSSLInfo)
	//rcv_reorder := make(map[int][]*PckSSLInfo)

	for _, pck := range PacketTraces {
		if strings.Contains(pck.SrcIp, LocalIp_sub) {
			LocalIp = pck.SrcIp
			break
		} else if strings.Contains(pck.DstIp, LocalIp_sub) {
			LocalIp = pck.DstIp
			break
		}
	}
	// find the local ip address

	// inferring packet Lost according to packet retrans & fast retrans.
	// downloading flows --> only calculate lost packets from the server;
	// uploading flows --> only calculate lost packets from the host; (which should be rarer?)
	// problem is that there is a delay between packet retrans & changing congestion window size....
	// which might affect the packet Lost pattern because the rtt of different flows are different
	// (will look into it later,currently thinking of the feasibility of adding rtt into the methodology..)
	for _, pck := range PacketTraces {
		// get src & dst ports
		if _, ok := stream_list[pck.StreamId]; !ok {
			if pck.SrcIp == LocalIp {
				stream_list[pck.StreamId] = append(stream_list[pck.StreamId], pck.SrcPort, pck.DstPort)
			} else {
				stream_list[pck.StreamId] = append(stream_list[pck.StreamId], pck.DstPort, pck.SrcPort)
			}
		}

		if pck.TcpLen != 0 || !pck.IsAck || pck.IsPsh || pck.IsSyn {
			//not ack
			if pck.DstIp == LocalIp {
				if pck.TCPRetrans == true {
					tmp_pck := &Lost_Packet{Time: pck.Ts, Length: pck.TcpLen, SequenceNumber: pck.Seq, Islost: true}
					rcv[pck.StreamId] = append(rcv[pck.StreamId], tmp_pck)
				} else {
					tmp_pck := &Lost_Packet{Time: pck.Ts, Length: pck.TcpLen, SequenceNumber: pck.Seq, Islost: false}
					rcv[pck.StreamId] = append(rcv[pck.StreamId], tmp_pck)
				}
			} else if pck.SrcIp == LocalIp {
				if pck.TCPRetrans == true {
					tmp_pck := &Lost_Packet{Time: pck.Ts, Length: pck.TcpLen, SequenceNumber: pck.Seq, Islost: true}
					snt[pck.StreamId] = append(rcv[pck.StreamId], tmp_pck)
				} else {
					tmp_pck := &Lost_Packet{Time: pck.Ts, Length: pck.TcpLen, SequenceNumber: pck.Seq, Islost: false}
					snt[pck.StreamId] = append(rcv[pck.StreamId], tmp_pck)
				}

			}
		}
	}
	for stream_id, ports := range stream_list {
		Lost_streams[stream_id] = &LostStream{TStart: -1.0, TEnd: -1.0, Pck_FromHost: snt[stream_id], Pck_FromServer: rcv[stream_id], Downup: false, HostPort: ports[0], ServerPort: ports[1]}
	}
	return Lost_streams
}

//get all packets given a list of streamids
func GetPckfromStreams(nameprefix string, streamids []int) ([]*PckInfo, map[int]*RTT_Stream, map[int]*LostStream) {
	pfilename := getpcappath(nameprefix)
	stmprefix := []string{}
	for _, stm := range streamids {
		stmprefix = append(stmprefix, `tcp.stream==`+strconv.Itoa(stm))
	}
	stmfilter := `(` + strings.Join(stmprefix, " || ") + `)`
	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-E", `separator=,`,
		"-Tfields",
		"-e", "tcp.stream",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "ip.len",
		"-e", "tcp.len",
		"-e", "tcp.window_size",
		"-e", "tcp.analysis.retransmission",
		"-e", "tcp.analysis.lost_segment",
		"-e", "tcp.analysis.out_of_order",
		"-e", "tcp.seq",
		"-e", "tcp.ack",
		"-e", "tcp.flags",
		// insert tcp.flags.ack, if 0, ack packets
		"-e", "tcp.flags.ack",
		"-e", "tcp.flags.reset",
		"-e", "tcp.flags.push",
		"-e", "tcp.flags.syn",
		"-e", "tcp.analysis.fast_retransmission",
		"-Y", stmfilter)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		allpck := ParsePckfromTshark(out.String())
		return allpck, GetRtt(allpck), GetPckLost(allpck)

	} else {
		log.Println(stderr.String())
		log.Fatal(err)
		return nil, nil, nil
	}

}
func GetSSLPckfromTuples(nameprefix string, srcip, dstip, srcport, dstport string) []*PckSSLInfo {
	pfilename := getpcappath(nameprefix)
	stmfilter := `(ip.addr==` + srcip + `&&tcp.port==` + srcport + `&&ip.addr==` + dstip + `&&tcp.port==` + dstport + `)`
	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-d", `tcp.port==`+dstport+`,ssl`,
		"-E", `separator=|`,
		"-Tfields",
		"-e", "tcp.stream",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "ip.len",
		"-e", "tcp.len",
		"-e", "tcp.window_size",
		"-e", "tcp.analysis.retransmission",
		"-e", "tcp.analysis.lost_segment",
		"-e", "tcp.analysis.out_of_order",
		"-e", "tcp.seq",
		"-e", "tcp.ack",
		"-e", "tcp.flags",
		"-e", "ssl.record.content_type",
		"-e", "ssl.record.opaque_type",
		"-e", "ssl.record.version",
		"-e", "ssl.record.length",
		// insert tcp.flags.ack, if 0, ack packets
		"-e", "tcp.flags.ack",
		"-e", "tcp.flags.reset",
		"-e", "tcp.flags.push",
		"-e", "tcp.flags.syn",
		"-e", "tcp.analysis.fast_retransmission",
		"-Y", stmfilter)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return ParseSSLPckfromTshark(out.String())
	} else {
		log.Println(stderr.String())
		log.Fatal(err)
		return nil
	}

}

func ParsePckfromTshark(tsharkoutput string) []*PckInfo {
	allpck := []*PckInfo{}
	lines := strings.Split(tsharkoutput, "\n")
	for _, ln := range lines {
		if len(ln) > 1 {
			pck := strings.Split(ln, ",")
			stmid, _ := strconv.Atoi(pck[0])
			frameno, _ := strconv.Atoi(pck[1])
			ts, _ := strconv.ParseFloat(pck[2], 64)
			srcp, _ := strconv.Atoi(pck[5])
			dstp, _ := strconv.Atoi(pck[6])
			ipl, _ := strconv.Atoi(pck[7])
			tcpl, _ := strconv.Atoi(pck[8])
			cwin, _ := strconv.Atoi(pck[9])
			tmpseqnum, _ := strconv.ParseUint(pck[13], 10, 32)
			tmpacknum, _ := strconv.ParseUint(pck[14], 10, 32)
			seqnum := uint(tmpseqnum)
			acknum := uint(tmpacknum)
			allpck = append(allpck, &PckInfo{
				StreamId:   stmid,
				FrameNo:    frameno,
				Ts:         ts,
				SrcIp:      pck[3],
				DstIp:      pck[4],
				SrcPort:    srcp,
				DstPort:    dstp,
				IpLen:      ipl,
				TcpLen:     tcpl,
				Win:        cwin,
				TCPRetrans: flagtobool(pck[10]) && flagtobool(pck[20]),
				TCPLost:    flagtobool(pck[11]),
				TCPReOrder: flagtobool(pck[12]),
				Seq:        seqnum,
				Ack:        acknum,
				Flag:       pck[15],
				IsAck:      flagtobool(pck[16]),
				IsRst:      flagtobool(pck[17]),
				IsPsh:      flagtobool(pck[18]),
				IsSyn:      flagtobool(pck[19])})

		}
	}
	return allpck

}

func ParseSSLPckfromTshark(tsharkoutput string) []*PckSSLInfo {
	allpck := []*PckSSLInfo{}
	sslmap := make(map[int]*StreamSSLInfo)
	lines := strings.Split(tsharkoutput, "\n")
	for _, ln := range lines {
		if len(ln) > 1 {
			pck := strings.Split(ln, "|")
			stmid, _ := strconv.Atoi(pck[0])
			frameno, _ := strconv.Atoi(pck[1])
			ts, _ := strconv.ParseFloat(pck[2], 64)
			srcp, _ := strconv.Atoi(pck[5])
			dstp, _ := strconv.Atoi(pck[6])
			ipl, _ := strconv.Atoi(pck[7])
			tcpl, _ := strconv.Atoi(pck[8])
			cwin, _ := strconv.Atoi(pck[9])
			tmpseqnum, _ := strconv.ParseUint(pck[13], 10, 32)
			tmpacknum, _ := strconv.ParseUint(pck[14], 10, 32)
			seqnum := uint(tmpseqnum)
			acknum := uint(tmpacknum)

			sslctypelayers := []string{}
			if len(pck[16]) >0 {
				sslctypelayers = strings.Split(pck[16], ",")// ssl.record.content_type
			}

			sslotypelayers := []string{}
			if len(pck[17]) >0 {
				sslotypelayers = strings.Split(pck[17], ",") // ssl.record.opaque_type
			}

			sslcversion := []string{}
			if len(pck[18]) >0 {
				sslcversion = strings.Split(pck[18], ",") // ssl.record.version
			}

			sslclength := []string{}
			if len(pck[19]) >0 {
				sslclength = strings.Split(pck[19], ",") //ssl.record.length
			}

			if len(sslctypelayers) == 0 && len(sslotypelayers) > 0 {
				sslctypelayers = sslotypelayers //ack = reset
			}

			ssltype := -1
			if sslmap[stmid] == nil {
				sslmap[stmid] = &StreamSSLInfo{0, 0, ""}
			} else {
				if len(sslctypelayers) > 0 {
					tlsv, _ := strconv.ParseInt(sslcversion[0], 0, 64)
					if tlsv == 769 {
						//tls 1.0, client hello
						sslmap[stmid].Clientstate = 1
						sslmap[stmid].Clientip = pck[3]
					} else if tlsv == 771 && (sslmap[stmid].Clientstate < 2 || sslmap[stmid].Serverstate < 2) {
						for k, slen := range sslclength {
							ctype := 23
							if k < len(sslctypelayers) {
								ctype, _ = strconv.Atoi(sslctypelayers[k])
							}
							if (slen == "40" && ctype == 22) || ctype == 23 {
								//found encrypted handshake, or application data
								if sslmap[stmid].Clientip == pck[3] {
									sslmap[stmid].Clientstate = 2
								} else {
									sslmap[stmid].Serverstate = 2
								}
								ssltype = ctype
								break
							}
						}
					}
				}
			}
			if sslmap[stmid].Clientip == pck[3] && sslmap[stmid].Clientstate < 2 {
				ssltype = 22
			} else if sslmap[stmid].Clientip == pck[4] && sslmap[stmid].Serverstate < 2 {
				ssltype = 22
			} else if ssltype == -1 && sslmap[stmid].Clientip == "" {
				ssltype = 22
			} else if ssltype == -1 {
				ssltype = 23
			}
			//log.Println(frameno, ssltype, pck[16], sslctypelayers)
			/*
					if len(sslctypelayers[0]) > 0 {
						ssltype, _ = strconv.Atoi(pck[13])
					} else {
						if !sslhandshakedone {
							ssltype = 22
						}
					}

				if ssltype == 22 {
					log.Println(frameno, ssltype)
				}
			*/
			allpck = append(allpck, &PckSSLInfo{
				PckInfo: PckInfo{
					StreamId:   stmid,
					FrameNo:    frameno,
					Ts:         ts,
					SrcIp:      pck[3],
					DstIp:      pck[4],
					SrcPort:    srcp,
					DstPort:    dstp,
					IpLen:      ipl,
					TcpLen:     tcpl,
					Win:        cwin,
					TCPRetrans: flagtobool(pck[10]) && flagtobool(pck[24]),
					TCPLost:    flagtobool(pck[11]),
					TCPReOrder: flagtobool(pck[12]),
					Seq:        seqnum,
					Ack:        acknum,
					Flag:       pck[15],
					IsAck:      flagtobool(pck[20]),
					IsRst:      flagtobool(pck[21]),
					IsPsh:      flagtobool(pck[22]),
					IsSyn:      flagtobool(pck[23]),
				},
				SSLRecordType:   ssltype,
				SSL_client_ip:   sslmap[stmid].Clientip,
				SSL_clientstate: sslmap[stmid].Clientstate,
				SSL_serverstate: sslmap[stmid].Serverstate,
				Claimed:         false})

		}
	}
	return allpck
}

func GetHTTPfromStreams(nameprefix string, streamids []int) (map[int]*StreamInfo, map[string][]*StreamMap) {
	pfilename := getpcappath(nameprefix)
	keyfilename := Getkeypath(nameprefix)
	stmprefix := []string{}
	for _, stm := range streamids {
		stmprefix = append(stmprefix, `tcp.stream==`+strconv.Itoa(stm))
	}
	stmfilter := `(` + strings.Join(stmprefix, " || ") + `)`
	httpfilter := `(http.request || http.request.method==OPTIONS || http.response) && ` + stmfilter +``
	var out bytes.Buffer
	var stderr bytes.Buffer
	var cmd *exec.Cmd
	if len(keyfilename) > 0 {
		cmd = exec.Command(TsharkPath, "-nr", pfilename,
			"-E", `separator=;`,
			"-o", "ssl.keylog_file:"+keyfilename,
			//"-d", "tcp.port==6020-8080,ssl",
			"-o", "http.ssl.port:6020-8080",
			"-Tfields",
			"-e", "tcp.stream",
			"-e", "frame.number",
			"-e", "frame.time_epoch",
			"-e", "http.request.method",
			"-e", "http.request.uri",
			"-e", "http.response.code",
			"-Y", httpfilter)
	} else {
		cmd = exec.Command(TsharkPath, "-nr", pfilename,
			"-E", `separator=\;`,
			"-Tfields",
			"-e", "tcp.stream",
			"-e", "frame.number",
			"-e", "frame.time_epoch",
			"-e", "http.request.method",
			"-e", "http.request.uri",
			"-e", "http.response.code",
			"-Y", httpfilter)
	}
	log.Println("GetHTTPfromStreams command:", cmd)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		streammap := make(map[int]*StreamInfo)
		urimap := make(map[string][]*StreamMap)
		lines := strings.Split(out.String(), "\n")
		for _, ln := range lines {
			if len(ln) > 1 {
				httpline := strings.Split(ln, ";")
				log.Println("http request line: ",httpline)
				stmid, _ := strconv.Atoi(httpline[0])
				frameno, _ := strconv.Atoi(httpline[1])
				frameTs, _ := strconv.ParseFloat(httpline[2], 64)
				hmethod := httpline[3]
				huri := httpline[4]
				hcode := 0
				request := 0
				if hmethod == "" {
					//only parse response code for response
					hcode, _ = strconv.Atoi(httpline[5])
					request = 1
				}
				var tmpreq HRequest
				var tmpresp HResponse
				if stream, exist := streammap[stmid]; !exist {
					//new stream
					if request == 0 {
						//http request
						tmpreq = HRequest{
							FrameNum: frameno,
							Ts:       frameTs,
							Method:   hmethod,
							Uri:      huri,
						}
						tmpresp = HResponse{}
					} else {
						//http response. we got an response before seeing request...
						//assume request lost, make an empty request obj (framenum=0)
						tmpreq = HRequest{}
						tmpresp = HResponse{
							FrameNum: frameno,
							Ts:       frameTs,
							Code:     hcode,
							FrameEnd: 0,
						}
					}
					streammap[stmid] = &StreamInfo{StreamId: stmid, Request: []HRequest{tmpreq}, Response: []HResponse{tmpresp}}
					smap := &StreamMap{StreamId: stmid, ReqIdx: len(streammap[stmid].Request) - 1}
					if _, uexist := urimap[huri]; !uexist {
						//new uri
						urimap[huri] = []*StreamMap{smap}
					} else {
						urimap[huri] = append(urimap[huri], smap)
					}
				} else {
					if request == 0 {
						//new request on existing stream, persistent HTTP
						//set the end of previous response, we assume no HTTP pipelining here, unless we analysis the content length. However, this info may be chipped out because of snaplen
						stream.Response[len(stream.Response)-1].FrameEnd = frameno - 1
						//handle multiple request within one packet
						hmethodarr := strings.Split(hmethod, ",")
						huriarr := strings.Split(huri, ",")
						for hidx, hm := range hmethodarr {
							tmpreq = HRequest{
								FrameNum: frameno,
								Ts:       frameTs,
								Method:   hm,
								Uri:      huriarr[hidx],
							}
							stream.Request = append(stream.Request, tmpreq)
						}
						tmpresp = HResponse{}
						stream.Response = append(stream.Response, tmpresp)

						smap := &StreamMap{StreamId: stmid, ReqIdx: len(stream.Request) - 1}
						if _, uexist := urimap[huri]; !uexist {
							urimap[huri] = []*StreamMap{smap}
						} else {
							urimap[huri] = append(urimap[huri], smap)
						}
					} else {
						//response, check if the last request is filled
						lastresp := len(stream.Response) - 1
						for sidx, sresp := range stream.Response {
							if sresp.Ts == 0 {
								lastresp = sidx
								break
							}
						}
						if stream.Response[lastresp].Ts == 0 {
							stream.Response[lastresp] = HResponse{
								FrameNum: frameno,
								Ts:       frameTs,
								Code:     hcode,
								FrameEnd: 0,
							}
						} else {
							//last response is not empty, probably missing/unparseable request
							//assign frame number of response -1 as request. Other keep 0 or empty
							stream.Response[lastresp].FrameEnd = frameno - 2
							//tmpreq = HRequest{FrameNum: stream.Response[lastresp].FrameNum + 1}
							tmpreq = HRequest{FrameNum: frameno - 1}
							tmpresp = HResponse{
								FrameNum: frameno,
								Ts:       frameTs,
								Code:     hcode,
								FrameEnd: 0,
							}
							stream.Request = append(stream.Request, tmpreq)
							stream.Response = append(stream.Response, tmpresp)
							smap := &StreamMap{StreamId: stmid, ReqIdx: len(stream.Request) - 1}
							if _, uexist := urimap[""]; !uexist {
								urimap[huri] = []*StreamMap{smap}
							} else {
								urimap[huri] = append(urimap[huri], smap)
							}

						}
					}
				}

			}
		}
		return streammap, urimap
	} else {
		log.Println(out.String())
		log.Println(stderr.String())
		log.Fatal(err)
		return nil, nil
	}

}

func GetTCPStreamwithRange(allpckinfo []*PckInfo, streamno, framestart, frameend int) []*PckInfo {
	//extract packets given a stream no, the start frame and end frame.
	streampck := []*PckInfo{}
	tracelen := len(allpckinfo)
	//if the end of range is 0, set it to the end of trace
	if frameend == 0 {
		frameend = tracelen
	}
	for _, pck := range allpckinfo {
		if pck.StreamId == streamno && (pck.FrameNo >= framestart && pck.FrameNo <= frameend) {
			streampck = append(streampck, pck)
		}
	}
	return streampck
}

func GetTCPStreamwithRangePcap(nameprefix string, streamno, framestart, frameend int) []*PckInfo {
	pfilename := getpcappath(nameprefix)
	tcpfilter := `tcp.stream==` + strconv.Itoa(streamno) + ` && (frame.number>=` + strconv.Itoa(framestart) + ` && frame.number<=` + strconv.Itoa(frameend) + `)`
	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-E", `separator=,`,
		"-Tfields",
		"-e", "tcp.stream",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "ip.len",
		"-e", "tcp.len",
		"-e", "tcp.window_size",
		"-e", "tcp.analysis.retransmission",
		"-e", "tcp.analysis.lost_segment",
		"-e", "tcp.analysis.out_of_order",
		"-e", "tcp.flags.ack",
		"-e", "tcp.flags.reset",
		"-e", "tcp.flags.push",
		"-e", "tcp.flags.syn",
		"-e", "tcp.analysis.fast_retransmission",
		"-Y", tcpfilter)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	log.Println("Pull Stream", streamno)
	err := cmd.Run()
	log.Println("Pull Stream done", streamno)
	if err == nil {
		allpck := []*PckInfo{}
		lines := strings.Split(out.String(), "\n")
		for _, ln := range lines {
			if len(ln) > 1 {
				pck := strings.Split(ln, ",")
				stmid, _ := strconv.Atoi(pck[0])
				frameno, _ := strconv.Atoi(pck[1])
				ts, _ := strconv.ParseFloat(pck[2], 64)
				srcp, _ := strconv.Atoi(pck[5])
				dstp, _ := strconv.Atoi(pck[6])
				ipl, _ := strconv.Atoi(pck[7])
				tcpl, _ := strconv.Atoi(pck[8])
				cwin, _ := strconv.Atoi(pck[9])
				allpck = append(allpck, &PckInfo{
					StreamId:   stmid,
					FrameNo:    frameno,
					Ts:         ts,
					SrcIp:      pck[3],
					DstIp:      pck[4],
					SrcPort:    srcp,
					DstPort:    dstp,
					IpLen:      ipl,
					TcpLen:     tcpl,
					Win:        cwin,
					TCPRetrans: flagtobool(pck[10]) || flagtobool(pck[17]),
					TCPLost:    flagtobool(pck[11]),
					TCPReOrder: flagtobool(pck[12]),
					IsAck:      flagtobool(pck[13]),
					IsRst:      flagtobool(pck[14]),
					IsPsh:      flagtobool(pck[15]),
					IsSyn:      flagtobool(pck[16]),
				})

			}
		}
		return allpck
	} else {
		log.Println("Err at ", streamno)
		log.Println(stderr.String())
		log.Fatal(err)
		return nil
	}

}

func GetTCPStream(nameprefix string, streamno int) []*PckInfo {
	pfilename := getpcappath(nameprefix)
	tcpfilter := `tcp.stream==` + strconv.Itoa(streamno)
	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-E", `separator=,`,
		"-Tfields",
		"-e", "tcp.stream",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "ip.len",
		"-e", "tcp.len",
		"-e", "tcp.window_size",
		"-e", "tcp.analysis.retransmission",
		"-e", "tcp.analysis.lost_segment",
		"-e", "tcp.analysis.out_of_order",
		"-e", "tcp.flags.ack",
		"-e", "tcp.flags.reset",
		"-e", "tcp.flags.push",
		"-e", "tcp.flags.syn",
		"-e", "tcp.analysis.fast_retransmission",
		"-Y", tcpfilter)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	log.Println("Pull Stream", streamno)
	err := cmd.Run()
	log.Println("Pull Stream done", streamno)
	if err == nil {
		allpck := []*PckInfo{}
		lines := strings.Split(out.String(), "\n")
		for _, ln := range lines {
			if len(ln) > 1 {
				pck := strings.Split(ln, ",")
				stmid, _ := strconv.Atoi(pck[0])
				frameno, _ := strconv.Atoi(pck[1])
				ts, _ := strconv.ParseFloat(pck[2], 64)
				srcp, _ := strconv.Atoi(pck[5])
				dstp, _ := strconv.Atoi(pck[6])
				ipl, _ := strconv.Atoi(pck[7])
				tcpl, _ := strconv.Atoi(pck[8])
				cwin, _ := strconv.Atoi(pck[9])
				allpck = append(allpck, &PckInfo{
					StreamId:   stmid,
					FrameNo:    frameno,
					Ts:         ts,
					SrcIp:      pck[3],
					DstIp:      pck[4],
					SrcPort:    srcp,
					DstPort:    dstp,
					IpLen:      ipl,
					TcpLen:     tcpl,
					Win:        cwin,
					TCPRetrans: flagtobool(pck[10]) || flagtobool(pck[17]),
					TCPLost:    flagtobool(pck[11]),
					TCPReOrder: flagtobool(pck[12]),
					IsAck:      flagtobool(pck[13]),
					IsRst:      flagtobool(pck[14]),
					IsPsh:      flagtobool(pck[15]),
					IsSyn:      flagtobool(pck[16]),
				})
			}
		}
		return allpck
	} else {
		log.Println("Err at ", streamno)
		log.Println(stderr.String())
		log.Fatal(err)
		return nil
	}
}

func Throughput(indexts float64, dport int, stream StreamPcap, interval float64) ([]*PcapThroughput, []*PcapThroughput) {
	if len(stream.PckDump) >= 1 {
		downth := []*PcapThroughput{}
		upth := []*PcapThroughput{}
		var curinterval float64
		curinterval = math.Floor((stream.PckDump[0].Ts - indexts) / interval)
		initts := curinterval*interval + indexts
		//log.Println(indexts, stream.PckDump[0].Ts, initts, curinterval)
		currentdown := &PcapThroughput{STs: stream.PckDump[0].Ts, Slot: initts, ETs: 0, ByteTotal: 0, Tput: 0}
		currentup := &PcapThroughput{STs: 0, Slot: initts, ETs: 0, ByteTotal: 0, Tput: 0}
		var lastframe int
		var lastts float64
		for i := 0; i < len(stream.PckDump); i++ {
			pck := stream.PckDump[i]
			if pck.TcpLen > 0 {
				if pck.Ts < (curinterval+1)*interval+indexts {
					//uplink
					if pck.DstPort == dport {
						currentup.ByteTotal += pck.TcpLen
						currentup.ETs = pck.Ts
					} else {
						//downlink
						currentdown.ByteTotal += pck.TcpLen
						currentdown.ETs = pck.Ts
						lastframe = pck.FrameNo
						lastts = pck.Ts
					}
				} else {
					//currentup.Tput = (float64(currentup.ByteTotal) * 8 / interval) * ((currentup.ETs - currentup.STs) / interval)
					currentup.Tput = (float64(currentup.ByteTotal) * 8 / interval)
					//currentdown.Tput = (float64(currentdown.ByteTotal) * 8 / interval) * ((currentdown.ETs - currentdown.STs) / interval)
					currentdown.Tput = (float64(currentdown.ByteTotal) * 8 / interval)
					downth = append(downth, currentdown)
					upth = append(upth, currentup)
					curinterval = math.Floor((pck.Ts - indexts) / interval)
					if pck.DstPort == dport {
						currentup = &PcapThroughput{STs: pck.Ts, Slot: curinterval*interval + indexts, ETs: pck.Ts, ByteTotal: pck.TcpLen, Tput: 0}
						currentdown = &PcapThroughput{STs: pck.Ts, Slot: curinterval*interval + indexts, ETs: 0, ByteTotal: 0, Tput: 0}
					} else {
						currentup = &PcapThroughput{STs: pck.Ts, Slot: curinterval*interval + indexts, ETs: 0, ByteTotal: 0, Tput: 0}
						currentdown = &PcapThroughput{STs: pck.Ts, Slot: curinterval*interval + indexts, ETs: pck.Ts, ByteTotal: pck.TcpLen, Tput: 0}
					}

				}
			}
		}
		log.Println("PcapTh", stream.StreamId, stream.PckDump[0].Ts, lastts, lastts-stream.PckDump[0].Ts, lastframe, len(stream.PckDump))
		if currentup.Tput == 0 {
			//currentup.Tput = (float64(currentup.ByteTotal) * 8 / interval) * ((currentup.ETs - currentup.STs) / interval)
			currentup.Tput = (float64(currentup.ByteTotal) * 8 / interval)
			if currentup.STs > 0 && currentup.Tput > 0 {
				upth = append(upth, currentup)
			}
		}
		if currentdown.Tput == 0 {
			//currentdown.Tput = (float64(currentdown.ByteTotal) * 8 / interval) * ((currentdown.ETs - currentdown.STs) / interval)
			currentdown.Tput = (float64(currentdown.ByteTotal) * 8 / interval)
			if currentdown.STs > 0 && currentdown.Tput > 0 {
				downth = append(downth, currentdown)
			}
		}
		return downth, upth
	} else {
		return nil, nil
	}
}

func UploadThroughput(indexts float64, dport int, stream StreamPcap, interval float64) []*PcapThroughput {
	if len(stream.PckDump) > 1 {
		th := []*PcapThroughput{}
		var curinterval float64
		currentup := &PcapThroughput{STs: 0, Slot: 0, ETs: 0, ByteTotal: 0, Tput: 0}
		//		debugstream := []int{}
		log.Println("First packet ts", stream.PckDump[0].Ts, stream.PckDump[0].FrameNo)
		for i := 0; i < len(stream.PckDump); i++ {
			pck := stream.PckDump[i]
			if pck.DstPort == dport && pck.TcpLen > 0 {
				currentup.ByteTotal += pck.TcpLen
				if currentup.STs == 0 {
					currentup.STs = pck.Ts
				}
			}
			//			debugstream = append(debugstream, pck.FrameNo)
			if pck.SrcPort == dport {
				//				log.Println("Got response ts", pck.Ts, pck.FrameNo)
				currentup.ETs = pck.Ts
			}
		}
		startts := math.Floor((currentup.STs - indexts) / interval)
		if currentup.STs == 0 {
			startts = math.Floor((stream.PckDump[0].Ts - indexts) / interval)
		}
		if currentup.ETs == 0 {
			currentup.ETs = stream.PckDump[len(stream.PckDump)-1].Ts
		}

		curinterval = math.Round((currentup.ETs - indexts) / interval)
		initts := startts*interval + indexts
		//		endts := curinterval*interval + indexts
		currentup.Slot = initts
		if currentup.ByteTotal > 0 {
			//			log.Println(currentup.ByteTotal, "RRTime:", (currentup.ETs - stream.Request.Ts), stream.Request.FrameNum, stream.Response.FrameNum, stream.Response.FrameEnd)
			/*			if len(debugstream) > 100 {
							log.Println(debugstream[len(debugstream)-50:])
						} else {

							log.Println(debugstream)
						}*/
			AvgTput := float64(currentup.ByteTotal) * 8 / (currentup.ETs - stream.Request.Ts)
			log.Println("Fill range", startts, curinterval, stream.PckDump[0].Ts-indexts, currentup.ETs-indexts, currentup.ByteTotal, AvgTput)
			if startts == curinterval {
				tmp := &PcapThroughput{STs: currentup.STs, Slot: startts*interval + indexts, ETs: currentup.ETs, ByteTotal: currentup.ByteTotal, Tput: AvgTput}
				th = append(th, tmp)
			} else {
				for t := startts; t < curinterval; t++ {
					estimateth := AvgTput
					tmp := &PcapThroughput{STs: t*interval + indexts, Slot: t*interval + indexts, ETs: (t+1)*interval + indexts, ByteTotal: currentup.ByteTotal, Tput: estimateth}
					if currentup.STs > (t*interval+indexts) || currentup.ETs < ((t+1)*interval+indexts) {
						//cannot fill the entire slot
						if currentup.STs > (t*interval + indexts) {
							tmp.STs = currentup.STs
						}
						if currentup.ETs < (t+1)*interval+indexts {
							tmp.ETs = currentup.ETs
						}
						estimateth = AvgTput * (tmp.ETs - tmp.STs) / interval
						tmp.Tput = estimateth
					}
					//tmp := &PcapThroughput{STs: t*interval + indexts, ETs: (t+1)*interval + indexts, ByteTotal: currentup.ByteTotal, Tput: estimateth}
					log.Println("upth:", tmp.STs-indexts, tmp.ETs-indexts, tmp.Slot-indexts, tmp.Tput, (tmp.ETs-tmp.STs)/interval)

					th = append(th, tmp)
				}

			}
			log.Println("Pcap return:", th)
			return th
		} else {
			return nil
		}
	}
	return nil
}

func getpcappath(nameprefix string) string {
	ext := filepath.Ext(nameprefix)
	if ext == ".pcap" {
		return nameprefix
	} else {
		return nameprefix[:len(nameprefix)-len(ext)+1] + "pcap"
	}
	/*	//update to newer approach
		names := strings.Split(nameprefix, ".")
		names[len(names)-1] = "pcap"
		return strings.Join(names, ".")
	*/

}

func Getkeypath(nameprefix string) string {
	ext := filepath.Ext(nameprefix)
	if ext == ".key" {
		return nameprefix
	} else {
		kfile := nameprefix[:len(nameprefix)-len(ext)+1] + "key"
		_, err := os.Stat(kfile)
		if os.IsNotExist(err) {
			return ""
		} else {
			return kfile
		}
	}
}

func flagtobool(field string) bool {
	switch field {
	case "":
		return false
	case "1":
		return true
	default:
		return false
	}
}

func (sslp *PckSSLInfo) GetPckInfo() *PckInfo {
	return &PckInfo{
		StreamId:   sslp.StreamId,
		FrameNo:    sslp.FrameNo,
		Ts:         sslp.Ts,
		SrcIp:      sslp.SrcIp,
		DstIp:      sslp.DstIp,
		SrcPort:    sslp.SrcPort,
		DstPort:    sslp.DstPort,
		IpLen:      sslp.IpLen,
		TcpLen:     sslp.TcpLen,
		Win:        sslp.Win,
		Seq:        sslp.Seq,
		Ack:        sslp.Ack,
		Flag:       sslp.Flag,
		TCPRetrans: sslp.TCPRetrans,
		TCPLost:    sslp.TCPLost,
		TCPReOrder: sslp.TCPReOrder,
	}
}

//test if the pcap timestamp is within a time range
func WithTs(testPcapTs float64, traceTs int64, timerange int64) bool {
	stime := float64(traceTs-timerange) / 1000000
	etime := float64(traceTs+timerange) / 1000000
	if testPcapTs > stime && testPcapTs < etime {
		return true
	}
	return false
}

func FindHeaviestFlow(nameprefix string) (string, string, string) {
	pfilename := getpcappath(nameprefix)

	// use tshark to find the heaviest conversation
	cmd := exec.Command(TsharkPath, "-nr", pfilename, "-q", "-z", "conv,tcp", "-n")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err == nil {
		lines := strings.Split(out.String(), "\n")
		lines = lines[5:] // remove headers
		//sort lines to get the heaviest flow (there is only one flow )
		var stm_max, stm_id int = 0, 0
		for i, ln := range lines {
			//log.Println(ln)
			if len(ln) > 1 {
				space := regexp.MustCompile(`\s+`)

				flow := strings.Replace(ln, "<->", "", -1)
				s := space.ReplaceAllString(flow, " ")
				flow_new := strings.Split(s, " ")

				if len(flow_new) <= 4 {
					continue
				}

				stm_size, _ := strconv.Atoi(flow_new[3])
				if stm_size > stm_max {
					stm_max = stm_size
					stm_id = i
				}

			}
		}
		// extract ip_src, ip_dst, port_src
		flow_main := lines[stm_id]
		space := regexp.MustCompile(`\s+`)
		flow_new := strings.Replace(flow_main, "<->", "", -1)
		s := space.ReplaceAllString(flow_new, " ")
		flow_main_new := strings.Split(s, " ")
		// find the heaviest flow
		ip_local := strings.Split(flow_main_new[0], ":")[0]
		port_local := strings.Split(flow_main_new[0], ":")[1]
		ip_server := strings.Split(flow_main_new[1], ":")[0]
		//port_server := strings.Split(flow_main_new[1], ":")[1]
		return ip_local, port_local, ip_server

	} else {
		log.Println(out.String())
		log.Println(stderr.String())
		log.Fatal(err)
		return "", "", ""
	}
}
func FindHeaviestDLULFlows(nameprefix string, clientip string) (*TCPFlow, *TCPFlow) {
	pfilename := getpcappath(nameprefix)

	// use tshark to find the heaviest conversation
	cmd := exec.Command(TsharkPath, "-nr", pfilename, "-q", "-z", "conv,tcp", "-n")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err == nil {
		lines := strings.Split(out.String(), "\n")
		lines = lines[5:] // remove headers
		//sort lines to get the heaviest flow (there is only one flow )
		uploadflow := &TCPFlow{}
		downloadflow := &TCPFlow{}
		uploadmax := 0
		downloadmax := 0

		for _, ln := range lines {
			if len(ln) > 1 {
				space := regexp.MustCompile(`\s+`)
				flow := strings.Replace(ln, "<->", "", -1)
				s := space.ReplaceAllString(flow, " ")
				flow_new := strings.Split(s, " ")

				if len(flow_new) <= 4 {
					continue
				}
				var tmpupload, tmpdownload int = 0, 0
				var tmpclientside, tmpserverside string
				if strings.Contains(flow_new[0], clientip) {
					//first column is the client IP
					tmpupload, _ = strconv.Atoi(flow_new[5])
					tmpdownload, _ = strconv.Atoi(flow_new[3])
					tmpclientside = flow_new[0]
					tmpserverside = flow_new[1]
				} else if strings.Contains(flow_new[1], clientip) {
					tmpupload, _ = strconv.Atoi(flow_new[3])
					tmpdownload, _ = strconv.Atoi(flow_new[5])
					tmpclientside = flow_new[1]
					tmpserverside = flow_new[0]
				} else {
					continue
				}
				cside := strings.Split(tmpclientside, ":")
				sside := strings.Split(tmpserverside, ":")
				if tmpupload > uploadmax {
					uploadflow.SrcIp = cside[0]
					uploadflow.SrcPort = cside[1]
					uploadflow.DstIp = sside[0]
					uploadflow.DstPort = sside[1]
					uploadmax = tmpupload
				}
				if tmpdownload > downloadmax {
					downloadflow.SrcIp = cside[0]
					downloadflow.SrcPort = cside[1]
					downloadflow.DstIp = sside[0]
					downloadflow.DstPort = sside[1]
					downloadmax = tmpdownload
				}
			}
		}
		// extract ip_src, ip_dst, port_src
		//flow_main := lines[stm_id]
		//space := regexp.MustCompile(`\s+`)
		//flow_new := strings.Replace(flow_main, "<->", "", -1)
		//s := space.ReplaceAllString(flow_new, " ")
		//flow_main_new := strings.Split(s, " ")
		// find the heaviest flow
		//ip_local := strings.Split(flow_main_new[0], ":")[0]
		//port_local := strings.Split(flow_main_new[0], ":")[1]
		//ip_server := strings.Split(flow_main_new[1], ":")[0]
		//port_server := strings.Split(flow_main_new[1], ":")[1]
		return uploadflow, downloadflow

	} else {
		log.Println(out.String())
		log.Println(stderr.String())
		log.Fatal(err)
		return nil, nil
	}
}

//this is only for speedofme
func HTTPSStream(nameprefix string, download_num int) (map[int]*HS_StreamInfo, map[int][]*PckInfo, int) {
	pfilename := getpcappath(nameprefix)

	ip_local, port_local, ip_server := FindHeaviestFlow(nameprefix)
	log.Println("found the heaviest flow")
	// -Y 'ip.addr == 192.172.226.100  &&  ip.addr == 72.21.81.189 && tcp.port == 52170'

	ip_src_string := "ip.addr == " + ip_local
	ip_dst_string := "ip.addr == " + ip_server
	port_src_string := "tcp.port ==" + port_local
	tls_string := "not ssl.handshake && frame.len != 54 && frame.len != 60"

	Httpsfilter := `(` + ip_src_string + "&&" + ip_dst_string + "&&" + port_src_string + "&&" + tls_string + `)`
	//use tshark to filter pcap traces

	cmd := exec.Command(TsharkPath, "-nr", pfilename,
		"-E", `separator=,`,
		"-Tfields",
		"-e", "frame.number", // frame sequence number
		//"-e", "_ws.col.Time", 		// frame collomn time
		"-e", "frame.time_epoch",

		"-e", "ip.src", // source ip
		"-e", "ip.dst", // dest ip
		"-e", "tcp.srcport", // source port
		"-e", "tcp.dstport", // dest port
		"-e", "_ws.col.Protocol", // protocol, two types here, "TCP" "TLSv1.2"
		"-e", "frame.len", // length of packet
		"-Y", Httpsfilter)
	//cmd := exec.Command(TsharkPath, "-nr",pfilename, "-Y",  Httpsfilter)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()

	//return value
	streammap := make(map[int]*HS_StreamInfo)
	allpck_stream := make(map[int][]*PckInfo)
	pck_num := 0
	if err == nil {
		lines := strings.Split(out.String(), "\n")
		//streammap := make(map[int]bool)
		//streamids := []int{}
		allpck := []*PckInfo{}
		for _, ln := range lines {
			if len(ln) > 1 {
				pck_num += 1
				pck := strings.Split(ln, ",")
				pck_id, _ := strconv.Atoi(pck[0])
				pck_time, _ := strconv.ParseFloat(pck[1], 64)
				ip_src := pck[2]
				ip_dst := pck[3]
				port_src, _ := strconv.Atoi(pck[4])
				port_dst, _ := strconv.Atoi(pck[5])
				pck_proto := pck[6]
				//there is no proto field in pckinfo
				fakeiplen := 0
				if pck_proto == "TLSv1.2" {
					fakeiplen = 99
				}
				pck_len, _ := strconv.Atoi(pck[7])
				//pck_info := strings.Join(pck[8:]," ")
				allpck = append(allpck, &PckInfo{
					FrameNo: pck_id,
					Ts:      pck_time,
					SrcIp:   ip_src,
					DstIp:   ip_dst,
					//Proto:	pck_proto,
					IpLen:   fakeiplen,
					TcpLen:  pck_len,
					SrcPort: port_src,
					DstPort: port_dst})
			}
		}

		var Flag_request = false
		var Flag_response = false
		var Flag_data = false
		var Flag_download = true
		var Flag_pre = true
		pre_flow_count := 0
		var pck_count uint = 0
		var all_download_pck_count uint = 0
		var all_download_byte_count uint = 0
		var all_upload_pck_count uint = 0
		var all_upload_byte_count uint = 0
		var stream_id int = 0 // current stream id from 0 to ......
		download_count := []uint{128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024, 2048 * 1024, 4096 * 1024, 8192 * 1024, 16384 * 1024, 32768 * 1024, 65536 * 1024, 131072 * 1024}
		download_count = download_count[:download_num-11]
		upload_count := []uint{8192 * 1024, 16384 * 1024, 32768 * 1024, 65536 * 1024, 131072 * 1024}
		for _, pck := range allpck {
			//if strings.Contains(pck.PacketInfo, "Retransmission") ||  strings.Contains(pck.PacketInfo, "Previous segment not captured") || strings.Contains(pck.PacketInfo, "Out-Of-Order"){
			//	continue
			//}

			// add streamid to allpck
			//pck.StreamId = stream_id
			//allpck_stream[stream_id] = append(allpck_stream[stream_id], pck)

			if Flag_pre {
				all_download_pck_count++
				all_download_byte_count += uint(pck.TcpLen)
				if Flag_request == false && pck.SrcIp == ip_local && pck.IpLen == 99 {
					Flag_request = true
					pck.StreamId = stream_id
					allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)

					//initiate stream map
					if pre_flow_count == 0 {
						tmpreq := HRequest{
							FrameNum: pck.FrameNo,
							Ts:       pck.Ts,
							Method:   "GET",
						}
						log.Println("Got Request", pck.FrameNo, pck.SrcIp)
						tmpresp := HResponse{}
						streammap[pck.StreamId] = &HS_StreamInfo{StreamId: stream_id, Request: []HRequest{tmpreq}, Response: []HResponse{tmpresp}, Downup: true}

					} else {
						tmpreq := HRequest{
							FrameNum: pck.FrameNo,
							Ts:       pck.Ts,
							Method:   "HEAD",
						}
						log.Println("Head Request", pck.FrameNo, pck.SrcIp)
						tmpresp := HResponse{}
						streammap[pck.StreamId] = &HS_StreamInfo{StreamId: stream_id, Request: []HRequest{tmpreq}, Response: []HResponse{tmpresp}, Downup: true}

					}

					continue
				} else if Flag_request == true && pck.SrcIp == ip_server && pck.IpLen == 99 {
					pck.StreamId = stream_id
					tmpresp := HResponse{
						FrameNum: pck.FrameNo,
						Ts:       pck.Ts,
						FrameEnd: 0,
					}
					allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)
					log.Println("Response", pck.FrameNo, pck.SrcIp)
					streammap[pck.StreamId].Response = []HResponse{tmpresp} // no need to use array here， may modify the structure later.
					pck_count += uint(pck.TcpLen)
					streammap[pck.StreamId].StreamLen += uint(pck.TcpLen)

					stream_id++
					pre_flow_count += 1
					if pre_flow_count == 11 {
						Flag_pre = false
						Flag_request = false
						continue
					} else {
						Flag_request = false
						continue
					}
				}
			}

			if Flag_download {
				all_download_pck_count++
				all_download_byte_count += uint(pck.TcpLen)
				if Flag_request == false && Flag_response == false && Flag_data == false {
					if pck.SrcIp == ip_local && pck.IpLen == 99 && pck.TcpLen > 0 {
						//request
						pck.StreamId = stream_id
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)

						Flag_request = true

						//initiate stream map
						tmpreq := HRequest{
							FrameNum: pck.FrameNo,
							Ts:       pck.Ts,
							Method:   "GET",
						}
						log.Println("Got Request", pck.StreamId, pck.FrameNo, pck.SrcIp)
						tmpresp := HResponse{}
						streammap[pck.StreamId] = &HS_StreamInfo{StreamId: stream_id, Request: []HRequest{tmpreq}, Response: []HResponse{tmpresp}, Downup: true}
						continue
					} else if pck.SrcIp == ip_server {
						if stream_id >= 1 {
							last_streamid := stream_id - 1
							pck.StreamId = last_streamid
							allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)
							//streammap[pck.StreamId].StreamLen += 1
							//streammap[pck.StreamId].StreamLen += uint(pck.TcpLen)
						}

					}
				}

				if Flag_request == true && Flag_response == false && Flag_data == false {
					if pck.SrcIp == ip_server && pck.IpLen == 99 && pck.TcpLen > 0 {
						/*						tmpresp := HResponse{
												FrameNum: pck.FrameNo,
												Ts:       pck.Ts,
												FrameEnd: 0,
											}*/
						pck.StreamId = stream_id
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)
						log.Println("Got Response", pck.StreamId, pck.FrameNo, pck.SrcIp)
						streammap[pck.StreamId].Response[0].FrameNum = pck.FrameNo
						streammap[pck.StreamId].Response[0].Ts = pck.Ts
						// no need to use array here， may modify the structure later.
						pck_count += uint(pck.TcpLen)
						//response
						Flag_request = false
						pck.StreamId = stream_id
						Flag_response = true
						continue
					}
				}

				if Flag_response == true || Flag_data == true {
					// download data
					if pck.TcpLen > 0 && pck.SrcIp == ip_server {
						pck.StreamId = stream_id
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)
						Flag_response = false
						Flag_data = true
						pck_count += uint(pck.TcpLen)

						if pck_count >= download_count[0] {
							stream_id++
							streammap[pck.StreamId].StreamLen = pck_count
							log.Println("Response length", pck_count)
							Flag_data = false
							download_count = download_count[1:]
							if len(download_count) == 0 {
								Flag_download = false
							}
							pck_count = 0
						}
					}
				}
			} else {
				//log.Println("Upload")
				all_upload_pck_count++
				all_upload_byte_count += uint(pck.TcpLen)
				if Flag_request == false && Flag_response == false && Flag_data == false {
					if pck.SrcIp == ip_local && pck.IpLen == 99 {
						//request
						pck.StreamId = stream_id
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)

						Flag_request = true

						//initiate stream map

						tmpreq := HRequest{
							FrameNum: pck.FrameNo,
							Ts:       pck.Ts,
							Method:   "POST",
						}
						log.Println("Post Request", pck.FrameNo, pck.SrcIp)
						streammap[pck.StreamId] = &HS_StreamInfo{StreamId: stream_id, Request: []HRequest{tmpreq}, Response: []HResponse{HResponse{}}, Downup: false}
						continue

					} else if pck.SrcIp == ip_server && stream_id == 11 && pck.IpLen == 99 {
						last_streamid := stream_id - 1
						pck.StreamId = last_streamid
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)

						streammap[pck.StreamId].StreamLen += uint(pck.TcpLen)
					} else if pck.SrcIp == ip_local {
						last_streamid := stream_id - 1
						pck.StreamId = last_streamid
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)

						streammap[pck.StreamId].StreamLen += uint(pck.TcpLen)
					}
				}
				if Flag_request == true && Flag_response == false && Flag_data == false {
					if pck.SrcIp == ip_server && pck.IpLen == 99 && pck.TcpLen < 1514 {
						tmpresp := HResponse{
							FrameNum: pck.FrameNo,
							Ts:       pck.Ts,
							FrameEnd: 0,
						}
						pck.StreamId = stream_id
						streammap[pck.StreamId].Response = []HResponse{tmpresp} // no need to use array here， may modify the structure later.
						pck_count += uint(pck.TcpLen)
						log.Println("Post Response", pck.StreamId, pck.FrameNo, pck.SrcIp)
						//response
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)
						Flag_request = false
						Flag_response = true
						continue
					} else if pck.SrcIp == ip_server && stream_id == 11 && pck.IpLen == 99 {
						last_streamid := stream_id - 1
						pck.StreamId = last_streamid
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)

						streammap[pck.StreamId].StreamLen += uint(pck.TcpLen)
					} else if pck.SrcIp == ip_local && pck.IpLen == 99 {
						last_streamid := stream_id - 1
						pck.StreamId = last_streamid
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)

						streammap[pck.StreamId].StreamLen += uint(pck.TcpLen)
					}
				}
				if Flag_response == true || Flag_data == true {
					if pck.TcpLen > 0 && pck.SrcIp == ip_local {
						pck.StreamId = stream_id
						allpck_stream[pck.StreamId] = append(allpck_stream[pck.StreamId], pck)
						Flag_response = false
						Flag_data = true
						pck_count += uint(pck.TcpLen)

						if pck_count >= upload_count[0] {
							stream_id++
							Flag_data = false
							streammap[pck.StreamId].StreamLen = pck_count

							pck_count = 0
							upload_count = upload_count[1:]
							if len(upload_count) == 0 {
								break
							}
						}
					}
				}

			}

		}
		log.Println("tshark statics: ")
		log.Println("the number of download streams is ", download_num-len(download_count))
		log.Println("the number of download packets is ", all_download_pck_count)
		log.Println("the number of download bytes is ", all_download_byte_count)
		for id, s := range streammap {
			if s.Downup {
				log.Println("pck_count in download streams", id, s.StreamLen)
			} else {
				log.Println("pck_count in upload streams", id, s.StreamLen)
			}
		}

		log.Println("the number of upload streams is ", 5-len(upload_count))

		log.Println("the number of upload packets is ", all_upload_pck_count)
		log.Println("the number of upload bytes is ", all_upload_byte_count)
	}
	return streammap, allpck_stream, pck_num

}

//return true of packet has FIN or RST set
func CheckTcpRstFin(tflag string) bool {
	var finrstmask uint64 = 0x05
	pflag, _ := strconv.ParseUint(tflag, 0, 8)
	if (pflag & finrstmask) != 0 {
		return true
	}
	return false

}

//tshark  -nr comcast_1539367807.pcap -Tfields -e tcp.stream -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -Y 'http.request.uri contains "/downloads"'

//tshark  -nr comcast_1539367807.pcap -Y 'dns.qry.name=="speedtest.xfinity.com" &&dns.flags==0x0100'

