package ookla

import (
	//"bytes"
	"cloudanalysis/common"
	"cloudanalysis/netlog"
	"cloudanalysis/savedata"
	"cloudanalysis/tracelog"
	"cloudanalysis/tsharkutil"
	"encoding/json"
	"net/url"

	//"io"
	"log"
	//"math"
	//"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//type Timeline tracelog.Timeline
//type FlowDetail tracelog.FlowDetail

/*type Timeline struct {
	Ts     int64
	Length float64
}

type FlowDetail struct {
	ReqTs       int64
	RespTs      int64
	Method      string
	StatusCode  int
	Priority    string
	Timing      tracelog.RespTiming
	RrsTimeline []Timeline
}*/

type OoklaMeasFlow struct {
	Url         string
	Host        string
	Port        string
	SrcPort     string
	DstIp       string
	ReqId       string
	OptionReqId string
	//	Random    string
	RangeLen  int
	DownUp    int
	Rrs       tracelog.FlowDetail
	XhrTiming tracelog.XhrFlow
	PcapInfo  tsharkutil.StreamPcap
}

//create a tmp place before we can see resource request
/*type XhrMeta struct {
	ReqId  string
	Unsent int64
	Opened int64
}*/

type TLSLeftOver struct {
	FrameNo  int
	PckKey   int
	ByteData int
}

type OoklaMetaTiming struct {
	Index         int64
	IndexPcap     float64
	DownloadStart int64
	DownloadEnd   int64
	UploadStart   int64
	UploadEnd     int64
}

type OoklaTest struct {
	Meta            *OoklaMetaTiming
	Flowmap         map[string]*OoklaMeasFlow
	CounterTimeline []*tracelog.Counters
	pck_num         int
	rttlist         map[int]*tsharkutil.RTT_Stream
}

type verified struct {
	Total          int
	Correct        int
	Incorrect      int
	Resp_correct   int
	Resp_incorrect int
	Req_correct    int
	Req_incorrect  int
}

//old: https://speedtest.rd.sd.cox.net:8080/download?nocache=b792a981-0071-48d3-8801-ab18eeab6cfe&size=25000000
//new: https://speedtest.spacelink.com.prod.hosts.ooklaserver.net:8080/download?nocache=b533d61f-c26a-40da-85b6-20e1665fdad7&size=25000000&guid=3fe59b0d-b9bd-4157-9f43-509550cfce5
var downloadUrlRegex = regexp.MustCompile(`^https://(\S+):(\d+)/download\?nocache=([\w-]+)&size=(\d+)&guid=([\w-]+)`)

//new: https://speedtest.spacelink.com.prod.hosts.ooklaserver.net:8080/upload?nocache=a7919a62-d1a0-4da1-9a73-648386f2254a&guid=3fe59b0d-b9bd-4157-9f43-509550cfce5a
var uploadUrlRegex = regexp.MustCompile(`^https://(\S+)\:(\d+)/upload\?nocache=([\w-]+)&guid=([\w-]+)`)

//see some hello probes to server
//old: https://speedtest.rd.sd.cox.net:8080/hello?nocache=5be2547b-8a32-46aa-a007-e92db3b25a86&guid=e1baf09e-24b0-41ef-950a-9996ac1750ef
var helloUrlRegex = regexp.MustCompile(`^https://(\S+)\:(\d+)/hello\?nocache=([\w-]+)&guid=([\w-]+)`)

var downloadUriRegex = regexp.MustCompile(`^/download\?nocache=(\S+)&size=(\d+)&guid=([\w-]+)`)
var uploadUriRegex = regexp.MustCompile(`^/upload\?nocache=([\w-]+)&guid=([\w-]+)`)

var pathhints []string = []string{"/download", "/upload", "/hello"}

const indexurl = "https://speedtest.xfinity.com/"

var hostipmap map[string]string
var hostports = []string{}

func compareRange(accdata uint, rangelen, progresslen int, tls_overhead int) int {
	if rangelen == -1 {
		//unknown range, accept anything
		return -1
	}
	var tmp_tls_overhead int
	if tls_overhead <= 0 {
		tmp_tls_overhead = 22
	} else {
		tmp_tls_overhead = tls_overhead
	}
	if rangelen < 1460 && accdata < 1460 {
		//smaller than 1 TCP packet, accept anything that can fit in 1 packet
		return 0
	} else {
		//adjustedrlen := uint((5+24)*progresslen + rangelen)
		adjustedrlen := uint((tmp_tls_overhead)*progresslen + rangelen)
		//		errp := float64((accdata - adjustedrlen)) / float64(adjustedrlen)

		if accdata < adjustedrlen {
			return -1
		} else if accdata == adjustedrlen {
			log.Println("Exact match", adjustedrlen)
			return 0
		} else {
			//accumluated data more than expected, and exceed margine
			log.Println("accdata > adjustedrlen", accdata, adjustedrlen)
			return int(accdata - adjustedrlen)
			//return 1
		}

		/*errp := math.Abs(float64((accdata - rangelen))) / float64(rangelen)
		if errp > errbound {
			return false
		}*/
	}
	return -1
}

func headerLength(header []string) int {
	h := strings.Join(header, "\r\n")
	return len(h) + 2
}

func LoadOokla(globwg *sync.WaitGroup, wchan chan int, filepath string, toverify bool) common.TestSummary {
	//	filepath := `/home/cskpmok/webspeedtestdata/US1/comcast/comcast_1539367807.json`
	log.Println("working on ", filepath)
	fileinfo := common.CheckDataFiles(filepath)
	//msgch := make(chan tracelog.PerfLog)
	//go tracelog.ReadLog(filepath, msgch)
	metatiming := common.MetaTiming{}
	allmflows := []*common.MeasFlow{}
	measflowmap := make(map[string]*common.MeasFlow)
	hostipmap = make(map[string]string)
	//we use the long string as "rand" in fast.com. it is not unique, but it can be used to distinguish measurement servers
	randidmap := make(map[string][]*common.MeasFlow)
	//
	//hostports := []string{}
	cnttimeline := []*tracelog.Counters{}
	var nlog *netlog.NetLogRecord = nil

	if fileinfo.NetlogExist {
		nlog = netlog.LoadNetLog(fileinfo.Netlog, indexurl, pathhints)
		metatiming.IndexNetlog = nlog.IndexTs // starting time
		log.Println("Total Netlog flow:", len(nlog.Flows))
		for nflowidx, nflow := range nlog.Flows {
			url := nflow.Url
			downup, urlobj := ParseOoklaURL(url)
			//log.Println("nflow info", nflowidx,nlog.Flows[nflowidx])
			mflow := &common.MeasFlow{Url: url, Host: urlobj[1], DstIp: nflow.FlowDetails.DstIP, Port: nflow.FlowDetails.DstPort, SrcIp: nflow.FlowDetails.SrcIP, SrcPort: nflow.FlowDetails.SrcPort, DownUp: downup, EvtId: nflow.EvtIds[0], NetLogInfo: nlog.Flows[nflowidx]}
			if downup == 0 {
				//get
				mflow.Random = urlobj[3] //random id, hash for ookla
				if len(nflow.Timing.Progress) > 0 {
					mflow.RangeLen = int(nflow.Timing.Progress[len(nflow.Timing.Progress)-1].LoadedByte) // the total bytes sent/received
				} else {
					mflow.RangeLen, _ = strconv.Atoi(urlobj[4])
				}
			} else if downup == 1 {
				// options or post
				mflow.Random = urlobj[3]
				if len(nflow.Timing.Progress) > 0 {
					mflow.RangeLen = int(nflow.Timing.Progress[len(nflow.Timing.Progress)-1].LoadedByte)
				} else {
					if nflow.Method == "OPTIONS" {
						mflow.RangeLen = 0
					} else {
						//mflow.RangeLen = -1
						mflow.RangeLen = 25000000 // for now, not sure if it is a good idea
					}
				}
			} else if downup == 2 {
				mflow.Random = urlobj[3] // hello probes
				mflow.RangeLen = 2
			}

			log.Println("random:", mflow.Random, "evtid:", nflow.EvtIds, "method:", nflow.Method, "Progresslen:", len(nflow.Timing.Progress), "RangeLen:", mflow.RangeLen, mflow.Host, mflow.DstIp, "Dport:", mflow.Port, "Sport:", mflow.SrcPort)
			if !contains(hostports, urlobj[2]) {
				hostports = append(hostports, urlobj[2])
			}
			if _, hexist := hostipmap[mflow.Host]; !hexist {
				hostipmap[mflow.Host] = mflow.DstIp
			}
			allmflows = append(allmflows, mflow)
			if _, mexist := randidmap[mflow.Random]; !mexist {
				randidmap[mflow.Random] = []*common.MeasFlow{mflow}
			} else {
				randidmap[mflow.Random] = append(randidmap[url], mflow)
			}
		}
		log.Println("hostipmap: ", hostipmap)
		log.Println("hostports: ", hostports)
		//sort each flowslice by evtid
		for randidx, _ := range randidmap {
			if len(randidmap[randidx]) > 1 {
				sort.SliceStable(randidmap[randidx], func(i, j int) bool { return randidmap[randidx][i].EvtId < randidmap[randidx][j].EvtId })
			}
		}
	}
	if fileinfo.TracelogExist {
		msgch := make(chan tracelog.PerfLog)
		go tracelog.ReadLog(filepath, msgch)
		loadtrace(msgch, &metatiming, measflowmap, randidmap, cnttimeline)
		if len(allmflows) == 0 {
			for midx, _ := range measflowmap {
				allmflows = append(allmflows, measflowmap[midx])
			}
		}
		mlen := 0
		for midx, _ := range measflowmap {
			log.Println("ReqId:", midx, "Url:", measflowmap[midx].Url)
			mlen++
		}
		log.Println("Done with Trace.", mlen)
	}
	//var allrtts map[int]*tsharkutil.RTT_Stream
	//var allpck_lost map[int]*tsharkutil.LostStream
	var allsslpcks int
	if fileinfo.PcapExist {
		allrtts, allpck_lost, allpcks := loadpcap(fileinfo, &metatiming, measflowmap, allmflows, toverify)
		allsslpcks = allpcks
		// save alllosts to json file
		err := savedata.SaveJSON(fileinfo.Tracelog, ".lost", allpck_lost)
		if err != nil {
			log.Panic(err)
		}
		err = savedata.SaveJSON(fileinfo.Tracelog, ".rtt", allrtts)
		if err != nil {
			log.Panic(err)
		}

	}
	/*
		for _, mv := range measflowmap {
			log.Println(mv.Url)
			log.Println(mv.Random, mv.ReqId, mv.Rrs.Method, mv.Rrs.ReqTs, mv.XhrTiming)
		}
	*/
	//get the timestamp of sending the DNS request
	//save data
	alldata := common.TestSummary{SourceFiles: fileinfo, Meta: &metatiming, Flows: allmflows, Flowmap: measflowmap, CounterTimeline: cnttimeline, PckNum: allsslpcks}
	err := savedata.SaveData(savedata.GobName(fileinfo.Tracelog), alldata)
	if err != nil {
		log.Fatal(err)
	}
	/*
		var buf bytes.Buffer

		enc := json.NewEncoder(&buf)
		enc.Encode(allpck_lost)
		paths := strings.Split(filepath, ".")
		lostPath := paths[0] + ".lost.json"
		f, erro := os.OpenFile(lostPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if erro != nil {
			log.Println(erro)
		}

		n, err := io.WriteString(f, buf.String())
		if err != nil {
			log.Println(n, err)
		}



		var buf1 bytes.Buffer

		enc1 := json.NewEncoder(&buf1)
		enc1.Encode(allrtts)
		RttPath := paths[0] + ".rtt.json"
		f1, erro1 := os.OpenFile(RttPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if erro1 != nil {
			log.Println(erro1)
		}

		n1, err1 := io.WriteString(f1, buf.String())
		if err1 != nil {
			log.Println(n1, err1)
		}
	*/
	return alldata
	//	log.Println(metatiming)
}

func loadtrace(msgch chan tracelog.PerfLog, metatiming *common.MetaTiming, measflowmap map[string]*common.MeasFlow, randreqidmap map[string][]*common.MeasFlow, cnttimeline []*tracelog.Counters) {
	keys := []int{}
	hostports := []string{}
	//hostipmap := make(map[string]string)

	for _, _ = range randreqidmap {
		keys = append(keys, 1)
	}
	//emptyflowmap := (len(keys) == 0)

	for l := range msgch {
		switch l.Name {
		case "UpdateCounters":
			var cnt tracelog.CounterData
			if err := json.Unmarshal(l.Args, &cnt); err == nil {
				ets := l.Ts - metatiming.Index
				counttime := &tracelog.Counters{Ts: ets, Listener: cnt.Data.JsListeners, HeapSize: cnt.Data.JsHeap}
				cnttimeline = append(cnttimeline, counttime)
			}
		case "ResourceSendRequest":
			var sndReq tracelog.RrsRequest
			if err := json.Unmarshal(l.Args, &sndReq); err == nil {
				if sndReq.Data.URL == "https://www.speedtest.net/" && metatiming.Index == 0 {
					// host redirect
					metatiming.Index = l.Ts
					break
				}
				downup, urlobj := ParseOoklaURL(sndReq.Data.URL)
				print("url", urlobj)
				if urlobj != nil {
					if _, exist := measflowmap[sndReq.Data.RequestID]; !exist {
						//update the rand flow mapping
						found := false
						urlhash := urlobj[3]
						openoption := ""
						if rmap, rexist := randreqidmap[urlhash]; rexist {
							for _, rmapobj := range rmap {
								if rmapobj.Rrs.Method == "OPTIONS" && rmapobj.OptionReqId == "" {
									openoption = rmapobj.ReqId
								}

								if l.Ts-metatiming.Index-rmapobj.XhrTiming.Opened < 1000 {
									//log.Println("Match sendrequest")
									measflowmap[sndReq.Data.RequestID] = rmapobj
									rmapobj.ReqId = sndReq.Data.RequestID
									found = true
									break
								}
							}
							//randreqidmap[urlobj[3]].ReqId = sndReq.Data.RequestID
						}
						if !found {
							newf := &common.MeasFlow{ReqId: sndReq.Data.RequestID}
							randreqidmap[urlhash] = append(randreqidmap[urlhash], newf)
							measflowmap[sndReq.Data.RequestID] = newf
							if sndReq.Data.RequestMethod == "POST" && openoption != "" {
								measflowmap[sndReq.Data.RequestID].OptionReqId = openoption
								measflowmap[openoption].OptionReqId = sndReq.Data.RequestID
								measflowmap[sndReq.Data.RequestID].XhrTiming = measflowmap[openoption].XhrTiming
							}

						}

						/*

							else {

								//mapping does not exist, probably cannot see the xhr
								newf := &ComcastMeasFlow{ReqId: sndReq.Data.RequestID}}
								randreqidmap[urlobj[3]] = &ComcastMeasFlow{ReqId: sndReq.Data.RequestID}
								measflowmap[sndReq.Data.RequestID] = randreqidmap[urlobj[3]]
							}*/
						//create a flow record
						measflowmap[sndReq.Data.RequestID].Url = urlobj[0]
						measflowmap[sndReq.Data.RequestID].Host = urlobj[1]
						measflowmap[sndReq.Data.RequestID].Port = urlobj[2]
						if len(urlobj[2]) > 1 && !contains(hostports, urlobj[2]) {
							hostports = append(hostports, urlobj[2])
						}
						//rnglen := 0
						//if downup == 0 {
						//	rnglen, _ = strconv.Atoi(urlobj[4])
						//} else if downup == 1 {
						//	rnglen = 10000000
						//} else if downup == 2 {
						//	//hello
						//	downup = 0
						//	rnglen = 0
						//}
						//measflowmap[sndReq.Data.RequestID].RangeLen = rnglen
						measflowmap[sndReq.Data.RequestID].DownUp = downup
						measflowmap[sndReq.Data.RequestID].Rrs = tracelog.FlowDetail{ReqTs: l.Ts - metatiming.Index, Method: sndReq.Data.RequestMethod, Priority: sndReq.Data.Priority}
					} else {
						//flow existed?
						log.Println("Dup flow ", sndReq.Data.RequestID)
					}
				}
			}
		case "ResourceReceiveResponse":
			var rcvRsp tracelog.RrsRecvResp
			if err := json.Unmarshal(l.Args, &rcvRsp); err == nil {
				rid := rcvRsp.Data.RequestID
				ets := l.Ts - metatiming.Index
				if _, exist := measflowmap[rid]; exist {
					measflowmap[rid].Rrs.RespTs = ets
					measflowmap[rid].Rrs.StatusCode = rcvRsp.Data.StatusCode
					measflowmap[rid].Rrs.Timing = rcvRsp.Data.Timing
					measflowmap[rid].Rrs.RrsTimeline = append(measflowmap[rid].Rrs.RrsTimeline, tracelog.Timeline{Ts: ets, Length: rcvRsp.Data.EncodedDataLength})
					if measflowmap[rid].DownUp == 0 {
						metatiming.DownloadEnd = ets
					} else {
						metatiming.UploadEnd = ets
					}
				}
			}
		case "ResourceReceivedData":
			var rcvData tracelog.RrsRcvData
			if err := json.Unmarshal(l.Args, &rcvData); err == nil {
				rid := rcvData.Data.RequestID
				if _, exist := measflowmap[rid]; exist {
					//log.Println("Match ", rid, rcvData.Data.EncodedDataLength)
					measflowmap[rid].Rrs.RrsTimeline = append(measflowmap[rid].Rrs.RrsTimeline, tracelog.Timeline{Ts: l.Ts - metatiming.Index, Length: rcvData.Data.EncodedDataLength})
				} else {
					//log.Println("Not match ", rid)
				}

			}
		case "ResourceFinish":
			var rcvFinish tracelog.RrsFinish
			if err := json.Unmarshal(l.Args, &rcvFinish); err == nil {
				rid := rcvFinish.Data.RequestID
				if _, exist := measflowmap[rid]; exist {
					measflowmap[rid].Rrs.RrsTimeline = append(measflowmap[rid].Rrs.RrsTimeline, tracelog.Timeline{Ts: l.Ts - metatiming.Index, Length: rcvFinish.Data.EncodedDataLength})
				}
			}

		case "XHRReadyStateChange":
			var xhrData tracelog.XhrReady
			if err := json.Unmarshal(l.Args, &xhrData); err == nil {
				downup, urlobj := ParseOoklaURL(xhrData.Data.URL)
				if urlobj != nil {
					urlhash := urlobj[3]
					// urlobj[1] suggests the port number
					//hostipmap[urlobj[1]] = ""
					ets := l.Ts - metatiming.Index
					switch xhrData.Data.ReadyState {
					case 0:
						if downup == 0 && metatiming.DownloadStart == 0 {
							metatiming.DownloadStart = ets
						} else if downup == 1 && metatiming.UploadStart == 0 {
							//need to fix to determine when the upload test starts
							metatiming.UploadStart = ets
						}
						tmp := &common.MeasFlow{}
						tmp.XhrTiming.Unsent = ets
						if _, exist := randreqidmap[urlhash]; !exist {
							//								randreqidmap[urlobj[3]] = &XhrMeta{ReqId: "", Unsent: l.Ts}
							randreqidmap[urlhash] = []*common.MeasFlow{tmp}
						} else {
							randreqidmap[urlhash] = append(randreqidmap[urlhash], tmp)
						}

					case 1:
						if downup == 0 && metatiming.DownloadStart == 0 {
							metatiming.DownloadStart = ets
						} else if downup == 1 && metatiming.UploadStart == 0 {
							metatiming.UploadStart = ets
						}
						if _, exist := randreqidmap[urlobj[3]]; !exist {
							tmp := &common.MeasFlow{}
							tmp.XhrTiming.Unsent = 0
							tmp.XhrTiming.Opened = ets
							randreqidmap[urlhash] = []*common.MeasFlow{tmp}
							//								randreqidmap[urlobj[3]] = &XhrMeta{ReqId: "", Unsent: 0, Opened: l.Ts}
						} else {
							var curflow *common.MeasFlow
							for _, tmpflow := range randreqidmap[urlhash] {
								if tmpflow.XhrTiming.Opened == 0 {
									curflow = tmpflow
									break
								}
							}
							if curflow != nil {
								curflow.XhrTiming.Opened = ets
							} else {
								tmp := &common.MeasFlow{}
								tmp.XhrTiming.Unsent = 0
								tmp.XhrTiming.Opened = ets
								randreqidmap[urlhash] = append(randreqidmap[urlhash], tmp)
							}
						}
					case 2:
						if rmap, exist := randreqidmap[urlhash]; exist {
							var tmpts int64
							tmpts = 0
							done := false
							sort.SliceStable(rmap, func(i, j int) bool { return rmap[i].XhrTiming.Opened < rmap[j].XhrTiming.Opened })
							for i := 0; i < len(rmap) && !done; i++ {
								rurl := rmap[i]
								//							for _, rurl := range rmap {
								if rurl.XhrTiming.Opened != 0 && rurl.XhrTiming.Header == 0 && rurl.Rrs.RespTs > 0 {
									if rurl.Rrs.Method == "OPTIONS" {
										tmpts = rurl.XhrTiming.Opened
									} else {
										if rurl.Rrs.Method == "POST" && tmpts > 0 {
											log.Println("Add back opents", rurl.ReqId)
											rurl.XhrTiming.Opened = tmpts
											tmpts = 0
										}
										done = true
									}

									rurl.XhrTiming.Header = ets
								}
							}
							/*for _, rurl := range rmap {
								if rurl.XhrTiming.Opened != 0 && rurl.Rrs.Method == "OPTIONS" {
									tmpts = rurl.XhrTiming.Opened
								}
								if rurl.XhrTiming.Header == 0 && len(rurl.XhrTiming.Loading) == 0 {
									rurl.XhrTiming.Header = ets
								}
								if rurl.Rrs.Method == "POST" && tmpts > 0 {
									//back fill open ts
									rurl.XhrTiming.Opened = tmpts
								}

							}*/
						}
					case 3:
						if rmap, exist := randreqidmap[urlhash]; exist {
							for _, rurl := range rmap {
								if rurl.XhrTiming.Done == 0 && rurl.Rrs.Method != "OPTIONS" {
									rurl.XhrTiming.Loading = append(rurl.XhrTiming.Loading, ets)
								}
							}
						}
					case 4:
						if rmap, exist := randreqidmap[urlhash]; exist {
							sort.SliceStable(rmap, func(i, j int) bool { return rmap[i].XhrTiming.Opened < rmap[j].XhrTiming.Opened })
							done := false
							for i := 0; i < len(rmap) && !done; i++ {
								rurl := rmap[i]
								//for _, rurl := range rmap {
								if rurl.XhrTiming.Done == 0 && rurl.Rrs.Method != "OPTIONS" {
									rurl.XhrTiming.Done = ets
									done = true
								}
							}
							/*for _, rurl := range rmap {
								if rurl.XhrTiming.Done == 0 {
									rurl.XhrTiming.Done = ets
								}
							}*/
						}
					}
				}

			}
		case "navigationStart":
			if metatiming.Index == 0 {
				metatiming.Index = l.Ts
			}
		}
	}
}

func loadpcap(fileinfo *common.FilePaths, metatiming *common.MetaTiming, measflowmap map[string]*common.MeasFlow, allmflows []*common.MeasFlow, toverify bool) (map[int]*tsharkutil.RTT_Stream, map[int]*tsharkutil.LostStream, int) {
	//get the timestamp of sending the DNS request
	its, _ := tsharkutil.DNSQueryTime(fileinfo.Pcap, "speedtest.net")
	if its == 0 {
		log.Println("Use HTTPS:", fileinfo.Pcap)
		its = tsharkutil.HTTPSSyncTime(fileinfo.Pcap)
	}
	metatiming.IndexPcap = its
	log.Println("Get DNS host IP")
	tsharkutil.DNSHostIP(fileinfo.Pcap, hostipmap)
	log.Println(hostipmap)
	log.Println("Get packets")
	// get rtt and ssl pcks (all encrypted pcks which matches corresbonding ip addresses)
	log.Println(hostports)
	allsslpcks, allrtts, allpck_lost := tsharkutil.GetSSLStreamsfromIPs(fileinfo.Pcap, hostipmap, hostports)
	allpcks_len := len(allsslpcks)

	//get unique stream ids
	streamidmap := make(map[int]*tsharkutil.StreamProgress)
	streamipmap := make(map[string][]*tsharkutil.StreamProgress)
	streamids := []int{}
	var tls_overhead int = -1

	for _, pck := range allsslpcks {
		if _, streamexist := streamidmap[pck.StreamId]; !streamexist {
			streamids = append(streamids, pck.StreamId)
			streamidmap[pck.StreamId] = &tsharkutil.StreamProgress{StreamId: pck.StreamId, PckIndex: 0}
			//assume first packet's dst IP is the measurement server ip
			streamipmap[pck.DstIp] = append(streamipmap[pck.DstIp], streamidmap[pck.StreamId])
		}
	}
	sort.Ints(streamids)
	log.Println("all packs num = ", allpcks_len, "unassigned packs num = ", allpcks_len)

	if allmflows[0].EvtId > 0 {
		//sort by event id
		sort.SliceStable(allmflows, func(i, j int) bool { return allmflows[i].EvtId < allmflows[j].EvtId })
	} else {
		//sort by request id
		sort.SliceStable(allmflows, func(i, j int) bool {
			rspliti := strings.Split(allmflows[i].ReqId, ".")
			rtaili, _ := strconv.Atoi(rspliti[1])
			rsplitj := strings.Split(allmflows[j].ReqId, ".")
			rtailj, _ := strconv.Atoi(rsplitj[1])
			return rtaili < rtailj
		})
	}
	/*
		for k, _ := range measflowmap {
			// k == flow_random_id
			rsplit := strings.Split(k, ".")
			reqprefix = rsplit[0]
			rtail, _ := strconv.Atoi(rsplit[1])
			reqidtail = append(reqidtail, rtail)
		}
		sort.Ints(reqidtail)
	*/

	flowremainbyte := make(map[int]*TLSLeftOver)

	for midx, _ := range allmflows {
		//		rid := reqprefix + "." + strconv.Itoa(ridt)
		curflow := allmflows[midx]
		if mip, ipexist := hostipmap[curflow.Host]; ipexist {
			assignedstream := 0
			//confirmed := false
			//accumdatalen := 0
			var startreqseq uint = 0
			var curreqseq uint = 0
			var startrespseq uint = 0
			var currespseq uint = 0
			reqdone := false
			respdone := false
			flowdone := false
			//revoke := false
			pendingpck := []*tsharkutil.PckSSLInfo{}
			log.Println("Working on ", curflow.Host, mip, curflow.Port, curflow.SrcPort, curflow.Rrs.ReqTs, curflow.OptionReqId, curflow.EvtId, curflow.Random)
			for pckkey := 0; pckkey < len(allsslpcks); pckkey++ {

				p := allsslpcks[pckkey]
				addpacket := true
				//flow not exist in excludeflow
				//ptime := tsharkutil.WithTs(p.Ts-metatiming.IndexPcap, curflow.Rrs.ReqTs, 1000000)

				//outgoing/incoming packet with matched source port
				if assignedstream == 0 && (p.DstIp == mip || p.SrcIp == mip) && ((strconv.Itoa(p.DstPort) == curflow.Port && strconv.Itoa(p.SrcPort) == curflow.SrcPort) || (strconv.Itoa(p.DstPort) == curflow.SrcPort && strconv.Itoa(p.SrcPort) == curflow.Port)) && !p.Claimed {
					// new flow matching!
					assignedstream = p.StreamId
					log.Println("flow ", curflow.ReqId, "evt ", curflow.EvtId, " binds to ", p.StreamId, " frame ", p.FrameNo, curflow.RangeLen, curflow.DownUp, curflow.NetLogInfo.Method)
					p.Claimed = true
					var req *tsharkutil.HRequest
					resp := &tsharkutil.HResponse{}
					//persistent http request, p.sslRecordType
					if p.TcpLen > 0 && p.SSLRecordType == 23 {
						if p.DstIp == mip {
							// persistent flow --> for comcast, should only appears for post and options
							uri := ""
							urlobj, err := url.Parse(curflow.NetLogInfo.Url)
							if err != nil {
								uri = urlobj.RequestURI()
							}
							log.Println("Found persistent request", p.FrameNo)
							req = &tsharkutil.HRequest{FrameNum: p.FrameNo, Ts: p.Ts, Method: curflow.NetLogInfo.Method, Uri: uri, FrameEnd: p.FrameNo}
							startreqseq = p.Seq + uint(p.TcpLen)
							curreqseq = p.Seq + uint(p.TcpLen)
							if fr, frexist := flowremainbyte[assignedstream]; frexist {
								if fr.ByteData >= headerLength(curflow.NetLogInfo.RequestHeader) {
									//next request header could be embeded in last packet of previous request
									log.Println("Found possibly combined request with", fr.FrameNo)
									startreqseq = allsslpcks[fr.PckKey].Seq + uint(allsslpcks[fr.PckKey].TcpLen)
									if fr.ByteData-headerLength(curflow.NetLogInfo.RequestHeader) > 30 {
										log.Println("Data appended in second request", fr.ByteData, headerLength(curflow.NetLogInfo.RequestHeader))
										startreqseq = startreqseq - uint(fr.ByteData-headerLength(curflow.NetLogInfo.RequestHeader)-tls_overhead)
									}

									//reset the remaining byte
								}
								delete(flowremainbyte, assignedstream)
							}
							if curflow.NetLogInfo.Method == "GET" || curflow.NetLogInfo.Method == "OPTIONS" {
								reqdone = true
							}
						} else {
							//get a incoming data packet first, check for leftover bytes
							log.Println("Got incoming data first", p.FrameNo)
							if _, rbexist := flowremainbyte[assignedstream]; rbexist {
								if flowremainbyte[assignedstream].ByteData >= headerLength(curflow.NetLogInfo.RequestHeader) && curflow.NetLogInfo.Method == "OPTIONS" {
									//this request header snitched with the previous one, and only OPTIONS will suffer from this
									//roll back packet number
									pckkey = flowremainbyte[assignedstream].PckKey
									p = allsslpcks[pckkey]
									log.Println("Found possibly second request in packet", p.FrameNo)
									uri := ""
									urlobj, err := url.Parse(curflow.NetLogInfo.Url)
									if err != nil {
										uri = urlobj.RequestURI()
									}
									req = &tsharkutil.HRequest{FrameNum: p.FrameNo, Ts: p.Ts, Method: curflow.NetLogInfo.Method, Uri: uri, FrameEnd: p.FrameNo}
									startreqseq = p.Seq + uint(p.TcpLen)
									curreqseq = p.Seq + uint(p.TcpLen)
									//possibly also embeded data
									if flowremainbyte[assignedstream].ByteData-headerLength(curflow.NetLogInfo.RequestHeader) > 30 {
										log.Println("Data appended in second request", headerLength(curflow.NetLogInfo.RequestHeader))
										startreqseq = startreqseq - uint(flowremainbyte[assignedstream].ByteData-headerLength(curflow.NetLogInfo.RequestHeader)-tls_overhead)
									}
									reqdone = true
								} else {
									log.Println("Insufficent leftover", p.FrameNo)
									//only valid for next request.
									addpacket = false
								}
								//remove remaining byte from map
								delete(flowremainbyte, assignedstream)
							}
						}
					} else {
						//otherwise it could be a SYN or other control packets
						req = &tsharkutil.HRequest{}
					}
					pendingpck = append(pendingpck, p)
					curflow.PcapInfo = tsharkutil.StreamPcap{StreamId: assignedstream, Request: req, Response: resp, PckDump: []*tsharkutil.PckInfo{p.GetPckInfo()}}
				} else {
					if assignedstream == p.StreamId && !p.Claimed {
						if p.FrameNo == 5889 {
							log.Println("5889", p.SSLRecordType, p.TcpLen, p.Claimed)
						}
						if p.FrameNo == 5888 {
							log.Println("5888", p.SSLRecordType, p.TcpLen, p.Claimed)
						}
						if curflow.PcapInfo.Request == nil {
							curflow.PcapInfo.Request = &tsharkutil.HRequest{}
						}
						if curflow.PcapInfo.Request.Ts == 0 {
							//still looking for the http request
							/*							if p.DstIp == mip && strconv.Itoa(p.DstPort) == curflow.Port {
														log.Println("found suspective request: ", p.FrameNo, p.TcpLen, p.SSLRecordType, p.SSL_client_ip, p.SSL_clientstate, p.SSL_serverstate)
													}*/
							if p.TcpLen > 0 && p.SSLRecordType == 23 && p.TcpLen >= 400 {
								if p.DstIp == mip && strconv.Itoa(p.DstPort) == curflow.Port {
									uri := ""
									urlobj, err := url.Parse(curflow.NetLogInfo.Url)
									if err != nil {
										uri = urlobj.RequestURI()
									}
									log.Println("Found request ", p.FrameNo)
									curflow.PcapInfo.Request.FrameNum = p.FrameNo
									curflow.PcapInfo.Request.FrameEnd = p.FrameNo
									curflow.PcapInfo.Request.Ts = p.Ts
									curflow.PcapInfo.Request.Method = curflow.Rrs.Method
									curflow.PcapInfo.Request.Uri = uri
									//if hello request, calculate tls overhead
									if curflow.RangeLen == 2 {
										if tls_overhead == -1 {
											var cur_overhead = p.TcpLen - len(curflow.NetLogInfo.RequestHeaderString)
											if cur_overhead >= 5 && cur_overhead <= 100 {
												tls_overhead = cur_overhead
												log.Println("Get tls overhead: ", tls_overhead)
											} else if cur_overhead <= 0 {
												log.Println("Fake tls overhead && request pkt", cur_overhead)
												curflow.PcapInfo.Request = nil
											}
										} else {
											var cur_overhead = p.TcpLen - len(curflow.NetLogInfo.RequestHeaderString)
											if cur_overhead != tls_overhead {
												log.Println("Found different tls overhead: ", cur_overhead, "old tls overhead is: ", tls_overhead)
												if cur_overhead <= 0 {
													log.Println("Fake tls overhead && request pkt", cur_overhead)
													curflow.PcapInfo.Request = nil
												}
											}
										}
									}
									//we found the request, clean up leftover
									delete(flowremainbyte, assignedstream)
									startreqseq = p.Seq + uint(p.TcpLen)
									curreqseq = p.Seq + uint(p.TcpLen)
									if curflow.PcapInfo.Request != nil && (curflow.NetLogInfo.Method == "GET" || curflow.NetLogInfo.Method == "OPTIONS") {
										reqdone = true
									}
								} else if p.SrcIp == mip && strconv.Itoa(p.SrcPort) == curflow.Port {
									//receive data before request?
									if _, rbexist := flowremainbyte[assignedstream]; rbexist {
										if flowremainbyte[assignedstream].ByteData >= headerLength(curflow.NetLogInfo.RequestHeader) && curflow.NetLogInfo.Method == "OPTIONS" {
											//this request header snitched with the previous one, and only OPTIONS will suffer from this
											//roll back packet number
											pckkey = flowremainbyte[assignedstream].PckKey
											p = allsslpcks[pckkey]
											log.Println("Found possibly second request in packet", p.FrameNo)
											uri := ""
											urlobj, err := url.Parse(curflow.NetLogInfo.Url)
											if err != nil {
												uri = urlobj.RequestURI()
											}

											curflow.PcapInfo.Request.FrameNum = p.FrameNo
											curflow.PcapInfo.Request.FrameEnd = p.FrameNo
											curflow.PcapInfo.Request.Ts = p.Ts
											curflow.PcapInfo.Request.Method = curflow.Rrs.Method
											curflow.PcapInfo.Request.Uri = uri
											startreqseq = p.Seq + uint(p.TcpLen)
											curreqseq = p.Seq + uint(p.TcpLen)
											//remove remaining byte from map
											delete(flowremainbyte, assignedstream)
											reqdone = true
										} else {
											log.Println("Insufficent leftover", p.FrameNo)
											//only valid for next request.
											delete(flowremainbyte, assignedstream)
											addpacket = false
										}
									} else {
										log.Println("Ignore Receive data before request", p.FrameNo)
										addpacket = false
									}
									//									revoke = true
								}
							}
						} else {
							if p.SrcIp == mip {
								//incoming packet
								if p.TcpLen > 0 && p.SSLRecordType == 23 {
									if curflow.PcapInfo.Response.Ts == 0 {
										//did not see response yet. assign response
										curflow.PcapInfo.Response.FrameNum = p.FrameNo
										curflow.PcapInfo.Response.FrameEnd = p.FrameNo
										curflow.PcapInfo.Response.Ts = p.Ts
										startrespseq = p.Seq
										currespseq = p.Seq + uint(p.TcpLen)
										log.Println("Found response ", p.FrameNo)
										if curflow.NetLogInfo.Method == "OPTIONS" || curflow.NetLogInfo.Method == "POST" {
											log.Println("POST/OPTIONS response done")
											respdone = true
											if p.Ack == curreqseq {
												//response packet already ack-ed all request packets
												flowdone = true
											}
										}
										if curflow.NetLogInfo.Method == "GET" && curflow.RangeLen == 2 && p.Ack == curreqseq {
											log.Println("Hello probe response done", p.Ack, curreqseq)
											respdone = true
											flowdone = true
										}
									} else {
										//only expect GET has multiple response packets
										if curflow.NetLogInfo.Method == "GET" {
											if !respdone {
												//push frameend forward
												curflow.PcapInfo.Response.FrameEnd = p.FrameNo
												currespseq = p.Seq + uint(p.TcpLen)
												switch diff := compareRange(currespseq-startrespseq, curflow.RangeLen, len(curflow.NetLogInfo.Timing.Progress), tls_overhead); {
												//switch compareRange(currespseq-startrespseq, curflow.RangeLen, 1, 0) {
												case diff == -1:
													//log.Println("Data on the way, not enough", p.FrameNo, int(currespseq-startrespseq), curflow.RangeLen)
												case diff == 0:
													log.Println("Received enough data", p.FrameNo, int(currespseq-startrespseq), curflow.RangeLen)
													respdone = true
												case diff >= 1:
													log.Println("Got more than enough data", p.FrameNo, int(currespseq-startrespseq), curflow.RangeLen)
													respdone = true
												}
											} else {
												//response already done
												log.Println("Ignore additional resposne packet GET", p.FrameNo)
												addpacket = false
											}
										} else {
											// HTTP method POST/OPTIONS
											log.Println("Ignore additional resposne packet POST/OPTIONS", p.FrameNo)
											addpacket = false
										}
									}
								}
								if reqdone {
									//handle pure ACK or RST
									if p.TcpLen == 0 && p.Ack >= curreqseq && !p.IsRst && curflow.NetLogInfo.Method == "POST" {
										log.Println("Handled all incoming Acks", p.FrameNo)
										flowdone = true
									}
									if p.IsRst {
										log.Println("Incoming RST", p.FrameNo)
										curflow.PcapInfo.Response.FrameEnd = p.FrameNo
										respdone = true
										reqdone = true
										flowdone = true
									}
								}
							} else if p.DstIp == mip {
								//outgoing packet
								if p.TcpLen > 0 && reqdone {
									//log.Println("Skip outgoing data", p.FrameNo)
									addpacket = false
								} else {

									if p.TcpLen > 0 && p.SSLRecordType == 23 {
										//handle POST
										if curflow.NetLogInfo.Method == "POST" && !reqdone {
											curreqseq = p.Seq + uint(p.TcpLen)
											if rbyte := compareRange(curreqseq-startreqseq, curflow.RangeLen, len(curflow.NetLogInfo.Timing.Progress)-1, tls_overhead); rbyte >= 0 {
												//if compareRange(curreqseq-startreqseq, curflow.RangeLen, 1, 0) > 0 {
												if rbyte > 0 {
													if _, rbexist := flowremainbyte[assignedstream]; !rbexist {
														flowremainbyte[assignedstream] = &TLSLeftOver{}
													}
													flowremainbyte[assignedstream].FrameNo = p.FrameNo
													flowremainbyte[assignedstream].PckKey = pckkey
													flowremainbyte[assignedstream].ByteData = rbyte
												}
												reqdone = true
												curflow.PcapInfo.Request.FrameEnd = p.FrameNo
												log.Println("POST Request done", p.FrameNo, int(curreqseq-startreqseq), curflow.RangeLen, len(curflow.NetLogInfo.Timing.Progress))
											}
										} else {
											//another outgoing packet for GET/OPTIONS? or Got more packet after POST reached expected length
											log.Println("Got extra outgoing packet", p.FrameNo)
											addpacket = false
											flowdone = true
										}
									}
								}
								if respdone {
									if p.TcpLen == 0 && p.Ack >= currespseq && !p.IsRst && curflow.NetLogInfo.Method == "GET" {
										log.Println("Handled all outgoing Acks", p.FrameNo)
										flowdone = true
									} else if p.IsRst {
										log.Println("Outgoing RST", p.FrameNo)
										respdone = true
										reqdone = true
										flowdone = true
									}
								}
							}
						}
						if pckkey > -1 && addpacket {
							//just claim all the packets in between
							pendingpck = append(pendingpck, p)
							p.Claimed = true
							curflow.PcapInfo.PckDump = append(curflow.PcapInfo.PckDump, p.GetPckInfo())
						}
						if reqdone && respdone && flowdone {
							log.Println("Flowdone", assignedstream)
							break
						}
						/*						if revoke {
													log.Println("Revoke ", assignedstream)
													assignedstream = 0
													accumdatalen = 0

													startreqseq = 0
													curreqseq = 0
													startrespseq = 0
													currespseq = 0
													revokeassignment(curflow, pendingpck)
													//do it all over again
													pckkey = -1
													revoke = false
													flowdone = false
													confirmed = false
												}
						*/
					}
				}
			}
			if assignedstream == 0 {
				log.Println("fail to assign stream to packets")
			}
		} else {
			log.Fatal("cannot match the hostname with IP", mip)
		}
	}
	//allocate downup to allrtts
	for mid, _ := range allmflows {
		flow := allmflows[mid]
		stream_id := flow.PcapInfo.StreamId
		if _, ok := allrtts[stream_id]; ok {
			log.Println("meaflow", flow.DownUp)
			allrtts[stream_id].Downup = !(flow.DownUp == 0) //convert int to bool
			allpck_lost[stream_id].Downup = allrtts[stream_id].Downup
			allpck_lost[stream_id].TStart = allrtts[stream_id].TStart
			allpck_lost[stream_id].TEnd = allrtts[stream_id].TEnd
			//true: up; false: down
		}
	}
	//log.Println(allrtts)

	log.Println("Done with tshark")
	return allrtts, allpck_lost, allpcks_len
}

func DecryptAnalysis(nameprefix string, cmtest *common.TestSummary) {
	log.Println("DecryptAnalysis")
	//if cmtest != nil {
	kfilename := tsharkutil.Getkeypath(nameprefix)
	if len(kfilename) > 0 {
		var total, correct, incorrect int = 0, 0, 0
		var req_correct, req_incorrect, resp_correct, resp_incorrect int = 0, 0, 0, 0
		streamidmap, streamurimap := tsharkutil.HTTPRequestStream(nameprefix, []string{"download?nocache", "upload?nocache", "/hello"})
		for suridx, suri := range streamurimap {
			log.Println("URI in pcap", suridx)
			for _, stmmap := range suri {
				log.Println("--", stmmap.StreamId)
			}
		}
		resp_framenum_map := make(map[int]bool)
		for _, stream := range streamidmap {
			for _, resp := range stream.Response {
				if resp.FrameNum != 0 {
					resp_framenum_map[resp.FrameNum] = true
				}
			}
		}
		log.Println("length of http ok", resp_framenum_map)
		for _, flow := range cmtest.Flows {
			total += 1
			u, err := url.Parse(flow.Url)
			log.Println("flow response: ", u, flow.PcapInfo.StreamId, flow.NetLogInfo.EvtIds, flow.PcapInfo.Response.FrameNum)
			if err != nil {
				log.Panic("Cannot parse URL", flow.Url)
			}
			if stm, sexist := streamidmap[flow.PcapInfo.StreamId]; sexist {
				//stm := streamidmap[stream.StreamId]
				log.Println("stm info: ", u.RequestURI(), stm.Request, stm.Response)
				for _, resp := range stm.Response {
					if flow.PcapInfo.StreamId == stm.StreamId && resp.FrameNum == flow.PcapInfo.Response.FrameNum {
						log.Println("response good match!", u.RequestURI(), 0, flow.NetLogInfo.Method, stm.StreamId, resp.FrameNum, flow.PcapInfo.Response.FrameNum)
						delete(resp_framenum_map, resp.FrameNum)
						correct += 1
						resp_correct += 1
						break
					}
				}
				//log.Println("stm response: ", stm.Response)

				for _, req := range stm.Request {
					if flow.PcapInfo.StreamId == stm.StreamId && req.Method == flow.NetLogInfo.Method && req.Uri == u.RequestURI() {
						if flow.PcapInfo.Request != nil {
							if req.Method == "GET" || req.Method == "OPTIONS" {
								if req.FrameNum == flow.PcapInfo.Request.FrameNum {
									//correct
									log.Println("request good match!", u.RequestURI(), 0, req.Method, stm.StreamId, req.FrameNum, flow.PcapInfo.Request.FrameNum)
									correct += 1
									req_correct += 1
								} else {
									log.Println("request wrong match!", u.RequestURI(), 0, req.Method, stm.StreamId, req.FrameNum, flow.PcapInfo.Request.FrameNum)
									incorrect += 1
									req_incorrect += 1
								}
							} else if req.Method == "POST" {
								if req.FrameNum == flow.PcapInfo.Request.FrameEnd {
									//correct
									log.Println("request good match!", u.RequestURI(), 0, req.Method, stm.StreamId, req.FrameNum, flow.PcapInfo.Request.FrameNum)
									correct += 1
									req_correct += 1
								} else {
									log.Println("request wrong match!", u.RequestURI(), 0, req.Method, stm.StreamId, req.FrameNum, flow.PcapInfo.Request.FrameNum)
									incorrect += 1
									req_incorrect += 1
								}

							}
						}
					}

				}

			} else {
				log.Println("URI not exist", u.RequestURI())
			}
		}
		if len(resp_framenum_map) != 0 {
			for fnum, _ := range resp_framenum_map {
				log.Println("response wrong match!", fnum)
			}
		}
		resp_incorrect = len(resp_framenum_map)
		log.Println("incorrect num:", incorrect+len(resp_framenum_map))
		log.Println("correct num:", correct)

		log.Println("incorrect request num:", req_incorrect)
		log.Println("correct request num:", req_correct)

		log.Println("incorrect response num:", resp_incorrect)
		log.Println("correct response num:", resp_correct)
		verify_res := verified{Total: total, Correct: correct, Incorrect: incorrect + len(resp_framenum_map), Req_correct: req_correct, Req_incorrect: req_incorrect,
			Resp_correct: resp_correct, Resp_incorrect: resp_incorrect}
		err := savedata.SaveJSON(common.CheckDataFiles(nameprefix).Tracelog, ".verify", verify_res)
		if err != nil {
			log.Panic(err)
		}
	} else {
		log.Println("no key available", nameprefix)
	}
	/*} else {
		log.Fatal("DecryptAnalysis: ComcastTest nil")
	}*/
}

//
//	//get the stream id of upload/download flows
//	//streamidmap, streamurimap := tsharkutil.HTTPRequestStream(filepath, []string{"downloads", "uploads"})
//	reqidtail := []int{}
//	reqprefix := ""
//	for midx, _ := range allmflows {
//		rsplit := strings.Split(k, ".")
//		reqprefix = rsplit[0]
//		rtail, _ := strconv.Atoi(rsplit[1])
//		reqidtail = append(reqidtail, rtail)
//	}
//	sort.Ints(reqidtail)
//	for _, ridt := range reqidtail {
//		rid := reqprefix + "." + strconv.Itoa(ridt)
//		curflow := measflowmap[rid]
//		if mip, ipexist := hostipmap[curflow.Host]; ipexist {
//			assignedstream := 0
//			confirmed := false
//			//exclude the first two flows, which is websocket connection
//			excludeflow := make(map[int]bool)
//			excludeflow[streamids[0]] = true
//			excludeflow[streamids[1]] = true
//			accumdatalen := 0
//			flowdone := false
//			//revoke := false
//			pendingpck := []*tsharkutil.PckSSLInfo{}
//			log.Println("Working on ", rid, curflow.Host, mip, curflow.Rrs.ReqTs)
//
//			for pckkey := 0; pckkey < len(allsslpcks); pckkey++ {
//				p := allsslpcks[pckkey]
//				_, xflow := excludeflow[p.StreamId]
//				//flow not exist in excludeflow
//				if !xflow {
//					ptime := tsharkutil.WithTs(p.Ts-metatiming.IndexPcap, curflow.Rrs.ReqTs, 500000)
//					if assignedstream == 0 && p.DstIp == mip && !p.Claimed && !excludeflow[p.StreamId] && ptime {
//						//						log.Println("range check:", p.Ts-metatiming.IndexPcap, curflow.Rrs.ReqTs, ptime)
//						assignedstream = p.StreamId
//						log.Println("flow ", curflow.ReqId, " binds to ", p.StreamId, " frame ", p.FrameNo)
//						p.Claimed = true
//						var req *tsharkutil.HRequest
//						resp := &tsharkutil.HResponse{}
//						//persistent http request
//						if p.TcpLen > 0 && p.SSLRecordType == 23 {
//							req = &tsharkutil.HRequest{FrameNum: p.FrameNo, Ts: p.Ts, Method: curflow.Rrs.Method, Uri: ""}
//						} else {
//							//otherwise it could be a SYN
//							req = &tsharkutil.HRequest{}
//						}
//						pendingpck = append(pendingpck, p)
//						curflow.PcapInfo = tsharkutil.StreamPcap{StreamId: assignedstream, Request: req, Response: resp, PckDump: []*tsharkutil.PckInfo{p.GetPckInfo()}}
//						curflow.SrcPort = strconv.Itoa(p.SrcPort)
//						curflow.DstIp = p.DstIp
//					} else {
//						if assignedstream == p.StreamId {
//							if curflow.PcapInfo.Request.Ts == 0 {
//								//still looking for the http request
//								if p.TcpLen > 0 && p.SSLRecordType == 23 {
//									if p.DstIp == mip {
//										log.Println("Found request ", p.FrameNo)
//										curflow.PcapInfo.Request.FrameNum = p.FrameNo
//										curflow.PcapInfo.Request.Ts = p.Ts
//										curflow.PcapInfo.Request.Method = curflow.Rrs.Method
//										curflow.PcapInfo.Request.Uri = ""
//									} else if p.SrcIp == mip {
//										//receive data before request?
//										log.Println("Revoke: receive data before request", p.FrameNo)
//										//revoke = true
//									}
//								}
//
//							} else {
//								//response header
//								if curflow.PcapInfo.Response.Ts == 0 {
//									if p.SrcIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 && !flowdone {
//										curflow.PcapInfo.Response.FrameNum = p.FrameNo
//										curflow.PcapInfo.Response.Ts = p.Ts
//										log.Println("Found response ", p.FrameNo)
//										//download. more packets should come in after header
//										if curflow.DownUp == 0 {
//											curflow.PcapInfo.Response.FrameEnd = 0
//										} else {
//											//upload, expect 1 data packet response.
//											if (curflow.Rrs.Method == "OPTIONS" && accumdatalen == 0) || (curflow.Rrs.Method == "POST" && accumdatalen > 100000) {
//												flowdone = true
//												curflow.PcapInfo.Response.FrameEnd = p.FrameNo
//											} else {
//												log.Println("Revoke: invalid incoming packet")
//												//revoke = true
//												flowdone = false
//											}
//										}
//									} else if p.DstIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 && !p.TCPRetrans {
//										//got another ongoing data packet
//										if curflow.Rrs.Method == "OPTIONS" {
//											log.Println("Revoke: receive unexpected ongoing packet", p.FrameNo)
//											//revoke = true
//											flowdone = false
//										} else {
//											//POST, expect more outgoing packets
//											accumdatalen += p.TcpLen
//										}
//									}
//								} else {
//									//we assigned response header. check for violation or adding data packets
//
//									if curflow.DownUp == 0 {
//										//download flows. we expect only incoming data packets.
//										if p.SrcIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 {
//											if !flowdone && !p.TCPRetrans {
//												//download flow. count new packets.
//												accumdatalen += p.TcpLen
//												//larger than the range parameter in http request
//												if accumdatalen > curflow.RangeLen {
//													log.Println("Response ends ", p.FrameNo)
//													curflow.PcapInfo.Response.FrameEnd = p.FrameNo
//													flowdone = true
//												}
//											}
//										} else if p.DstIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 {
//											errorpercent := math.Abs(float64(accumdatalen-curflow.RangeLen)) / float64(curflow.RangeLen)
//											if !flowdone {
//												if errorpercent > 0.5 {
//													//outgoing data before reaching expected data length, wrong assignment
//													log.Println("Revoke: outgoing data exceed length at frame", p.FrameNo, accumdatalen, curflow.RangeLen)
//													//revoke = true
//													flowdone = false
//												} else {
//													log.Println("accept with low margin", p.FrameNo, errorpercent)
//													curflow.PcapInfo.Response.FrameEnd = curflow.PcapInfo.PckDump[len(curflow.PcapInfo.PckDump)-1].FrameNo
//													flowdone = true
//													confirmed = true
//												}
//											} else {
//												//start of next request
//												confirmed = true
//											}
//										}
//									} else {
//										//we expect 1 incoming/outgoing for OPTIONS
//										//upload. we only expect outgoing data size is 10000000
//
//										if p.SrcIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 && !p.TCPRetrans {
//											//another incoming packet and not a retransmission. wrong flow
//											log.Println("Revoke: another incoming packet. wrong flow", p.FrameNo)
//											//revoke = true
//											flowdone = false
//										} else if p.DstIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 && !p.TCPRetrans {
//											//another outgoing, after found the response
//											confirmed = true
//										}
//									}
//								}
//								if flowdone && confirmed {
//									break
//								}
//							}
//							if pckkey > -1 {
//								//just claim all the packets in between
//								pendingpck = append(pendingpck, p)
//								p.Claimed = true
//								curflow.PcapInfo.PckDump = append(curflow.PcapInfo.PckDump, p.GetPckInfo())
//							}
//
//							//if revoke {
//							//	log.Println("Revoke ", assignedstream)
//							//	excludeflow[assignedstream] = true
//							//	assignedstream = 0
//							//	accumdatalen = 0
//							//	revokeassignment(curflow, pendingpck)
//							//	//do it all over again
//							//	pckkey = -1
//							//	revoke = false
//							//	flowdone = false
//							//	confirmed = false
//							//}
//
//						}
//					}
//				}
//			}
//			if assignedstream == 0 {
//				log.Println("fail to assign stream to packets")
//			}
//		} else {
//			log.Fatal("cannot match the hostname with IP", mip)
//		}
//	}
//
//	//allocate downup to allrtts
//	for rand_id,_:=range measflowmap{
//		flow,ok:= measflowmap[rand_id]
//		if ok{
//			stream_id := flow.PcapInfo.StreamId
//			if _,ok := allrtts[stream_id];ok{
//				log.Println("meaflow",measflowmap[rand_id].DownUp)
//				allrtts[stream_id].Downup = !(measflowmap[rand_id].DownUp==0) //convert int to bool
//				allpck_lost[stream_id].Downup = allrtts[stream_id].Downup
//				allpck_lost[stream_id].TStart  = allrtts[stream_id].TStart
//				allpck_lost[stream_id].TEnd = allrtts[stream_id].TEnd
//				//true: up; false: down
//			}
//		}
//	}
//	//log.Println(allrtts)
//
//	log.Println("Done with tshark")
//	return allrtts, allpck_lost, allpcks_len
//}

//	for rid, flow := range measflowmap {
/*	for _, flow := range measflowmap {
	var bytesize []float64
	var downtcpsize []float64
	var uptcpsize []float64
	for _, b := range flow.Rrs.RrsTimeline {
		bytesize = append(bytesize, b.Length)
	}
	for _, pb := range flow.PcapInfo.PckDump {
		//uplink
		if pb.SrcIp == cip {
			uptcpsize = append(uptcpsize, float64(pb.TcpLen))
		} else {
			downtcpsize = append(downtcpsize, float64(pb.TcpLen))
		}
	}
	log.Println(len(flow.PcapInfo.PckDump), len(flow.Rrs.RrsTimeline), floats.Sum(bytesize), floats.Sum(downtcpsize), floats.Sum(uptcpsize))
}*/
////save data
//alldata := OoklaTest{Meta: &metatiming, Flowmap: measflowmap, CounterTimeline: cnttimeline, pck_num: len(allsslpcks),rttlist:allrtts}
//err := savedata.SaveData(savedata.GobName(filepath), alldata)
//if err != nil {
//	log.Fatal(err)
//}

//// save allrtts to json file
//var buf bytes.Buffer
//
//enc := json.NewEncoder(&buf)
//enc.Encode(allrtts)
//paths :=strings.Split(filepath,".")
//RttPath := paths[0]+".rtt.json"
//f, erro := os.OpenFile(RttPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
//if erro != nil {
//	log.Println(erro)
//}
//
//n, err := io.WriteString(f, buf.String())
//if err != nil {
//	log.Println(n, err)
//}

// save alllosts to json file
// save alllosts to json file
//	var buf bytes.Buffer
//
//	enc := json.NewEncoder(&buf)
//	enc.Encode(allpck_lost)
//	paths :=strings.Split(filepath,".")
//	lostPath := paths[0]+".lost.json"
//	f, erro := os.OpenFile(lostPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
//	if erro != nil {
//		log.Println(erro)
//	}
//
//	n, err := io.WriteString(f, buf.String())
//	if err != nil {
//		log.Println(n, err)
//	}
//
//	var buf1 bytes.Buffer
//
//	enc1 := json.NewEncoder(&buf1)
//	enc1.Encode(allrtts)
//	RttPath := paths[0]+".rtt.json"
//	f1, erro1 := os.OpenFile(RttPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
//	if erro1 != nil {
//		log.Println(erro1)
//	}
//
//	n1, err1 := io.WriteString(f1, buf.String())
//	if err1 != nil {
//		log.Println(n1, err1)
//	}
//
//	return alldata
//
//	return alldata
//	//	log.Println(metatiming)
//}

func RunOoklaAnalysis(globwg *sync.WaitGroup, wchan chan int, filepath string, toverify bool) {
	var alldata common.TestSummary
	defer globwg.Done()
	common.Makeplotdir(filepath)
	if err := savedata.LoadData(savedata.GobName(filepath), &alldata); err != nil {
		alldata = LoadOokla(globwg, wchan, filepath, toverify)
	} else {
		log.Println("Found precomputed data")

		OoklaPlotFlow(filepath, alldata)
	}
	if toverify {
		DecryptAnalysis(filepath, &alldata)
		log.Println()
	}
	//OoklaPlotRRTime(filepath, alldata.Meta, alldata.Flowmap)
	//OoklaPlotFlow(filepath, alldata)
	//OoklaPlotUpload(filepath, alldata)
	<-wchan
}

//
func ParseOoklaURL(u string) (downup int, urls []string) {
	var urlobj []string
	downup = 0 //down
	if urlobj = downloadUrlRegex.FindStringSubmatch(u); urlobj == nil {
		if urlobj = helloUrlRegex.FindStringSubmatch(u); urlobj == nil {
			if urlobj = uploadUrlRegex.FindStringSubmatch(u); urlobj != nil {
				downup = 1 //upload or options
			}
		} else {
			downup = 2 //hello
		}
		//log.Println(urlobj)
	}
	return downup, urlobj

}

/*
func ParseOoklaURI(u string) (r string) {
	var uriobj []string
	if uriobj = downloadUriRegex.FindStringSubmatch(u); uriobj == nil {
		if uriobj = uploadUrlRegex.FindStringSubmatch(u); urlobj != nil {
			downup = 1
		} else {
			log.Fatal("URL not match", u)
		}
	}
	return strings.TrimSpace(uriobj[0])
}
*/
//func revokeassignment(mflow *OoklaMeasFlow, restorepck []*tsharkutil.PckSSLInfo) {
//	mflow.PcapInfo.StreamId = 0
//	mflow.PcapInfo.Request = nil
//	mflow.PcapInfo.Response = nil
//	mflow.PcapInfo.PckDump = nil
//	for _, p := range restorepck {
//		p.Claimed = false
//	}
//}
//
func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}
