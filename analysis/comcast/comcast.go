package comcast

import (
	"analysis/common"
	"analysis/netlog"
	"analysis/savedata"
	"analysis/tracelog"
	"analysis/tsharkutil"
	"encoding/json"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)


type TLSLeftOver struct {
	FrameNo  int
	PckKey   int
	ByteData int
}

type verified struct {
	Total int
	Correct int
	Incorrect int
	Resp_correct int
	Resp_incorrect int
	Req_correct int
	Req_incorrect int
}

var downloadUrlRegex = regexp.MustCompile(`^https://(\S+)\:(\d+)/api/downloads\?bufferSize=(\d+)\&r=([\d\.]+)`)
var uploadUrlRegex = regexp.MustCompile(`^https://(\S+)\:(\d+)/api/uploads\?r=([\d\.]+)`)

//var latencyUrlRegex =regexp.MustCompile(`^https://(\S+)/api/latencys\?([\d\.]+)`)
var downloadUriRegex = regexp.MustCompile(`^/api/downloads\?bufferSize=(\d+)\&r=([\d\.]+)`)
var uploadUriRegex = regexp.MustCompile(`^/api/uploads\?r=([\d\.]+)`)

var pathhints []string = []string{"/api/downloads", "/api/uploads"}

const indexurl = "https://speedtest.xfinity.com/"

var hostports []string = []string{}

var hostipmap map[string]string

func LoadComcast(globwg *sync.WaitGroup, wchan chan int, filepath string) common.TestSummary {
	log.Println("working on ", filepath)
	fileinfo := common.CheckDataFiles(filepath)
	metatiming := common.MetaTiming{}
	allmflows := []*common.MeasFlow{}
	randidmap := make(map[string][]*common.MeasFlow)
	measflowmap := make(map[string]*common.MeasFlow)
	hostipmap = make(map[string]string)
	cnttimeline := []*tracelog.Counters{}
	var nlog *netlog.NetLogRecord = nil

	if fileinfo.NetlogExist {
		nlog = netlog.LoadNetLog(fileinfo.Netlog, indexurl, pathhints)
		metatiming.IndexNetlog = nlog.IndexTs
		//we use main event Id here to for measflowmap
		log.Println("Total NetLog flow:", len(nlog.Flows))
		for nflowidx, nflow := range nlog.Flows {
			url := nflow.Url
			downup, urlobj := ParseComcastURL(url)
			mflow := &common.MeasFlow{Url: url, Host: urlobj[1], DstIp: nflow.FlowDetails.DstIP, Port: nflow.FlowDetails.DstPort, SrcIp: nflow.FlowDetails.SrcIP, SrcPort: nflow.FlowDetails.SrcPort, DownUp: downup, EvtId: nflow.EvtIds[0], NetLogInfo: nlog.Flows[nflowidx]}
			if downup == 0 {
				// get
				mflow.Random = urlobj[4]
				if len(nflow.Timing.Progress) > 0 {
					mflow.RangeLen = int(nflow.Timing.Progress[len(nflow.Timing.Progress)-1].LoadedByte)
				} else {
					mflow.RangeLen, _ = strconv.Atoi(urlobj[3])
				}
			} else {
				// options or post
				mflow.Random = urlobj[3]
				if len(nflow.Timing.Progress) > 0 {
					mflow.RangeLen = int(nflow.Timing.Progress[len(nflow.Timing.Progress)-1].LoadedByte)
				} else {
					if nflow.Method == "OPTIONS" {
						mflow.RangeLen = 0
					} else {
						mflow.RangeLen = -1
					}
				}
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

	var allsslpcks int
	if fileinfo.PcapExist {
		allrtts, allpck_lost, allpcks := loadpcap(fileinfo, &metatiming, measflowmap, allmflows)
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

	//get the timestamp of sending the DNS request
	//save data
	alldata := common.TestSummary{SourceFiles: fileinfo, Meta: &metatiming, Flows: allmflows, Flowmap: measflowmap, CounterTimeline: cnttimeline, PckNum: allsslpcks}
	err := savedata.SaveData(savedata.GobName(fileinfo.Tracelog), alldata)
	if err != nil {
		log.Fatal(err)
	}
	return alldata
}

func DecryptAnalysis(nameprefix string, cmtest *common.TestSummary) {
	log.Println("DecryptAnalysis")
	//if cmtest != nil {
	kfilename := tsharkutil.Getkeypath(nameprefix)
	if len(kfilename) > 0 {
		var total, correct, incorrect int = 0, 0, 0
		var req_correct, req_incorrect, resp_correct, resp_incorrect int = 0, 0, 0, 0

		streamidmap, streamurimap := tsharkutil.HTTPRequestStream(nameprefix, []string{"downloads", "uploads","hello"})
		for suridx, suri := range streamurimap {
			log.Println("URI in pcap", suridx)
			for _, stmmap := range suri {
				log.Println("--", stmmap.StreamId)
			}
		}
		resp_framenum_map := make(map[int]bool)
		for _, stream := range streamidmap{
			for _, resp := range stream.Response{
				if resp.FrameNum !=0 {
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
				log.Println("stm info: ", u.RequestURI() , stm.Request, stm.Response)
				for _, resp := range stm.Response{
					if flow.PcapInfo.StreamId == stm.StreamId && resp.FrameNum == flow.PcapInfo.Response.FrameNum{
						log.Println("response good match!", u.RequestURI(), 0, flow.NetLogInfo.Method, stm.StreamId, resp.FrameNum, flow.PcapInfo.Response.FrameNum)
						delete(resp_framenum_map, resp.FrameNum)
						correct += 1
						resp_correct +=1
						break
					}
				}
				//log.Println("stm response: ", stm.Response)

				for _, req := range stm.Request {
					if flow.PcapInfo.StreamId == stm.StreamId && req.Method == flow.NetLogInfo.Method && req.Uri == u.RequestURI() {
						if flow.PcapInfo.Request != nil {
							if req.Method == "GET" || req.Method == "OPTIONS"{
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
							}else if req.Method == "POST" {
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
		if len(resp_framenum_map) != 0{
			for fnum, _ := range(resp_framenum_map){
				log.Println("response wrong match!", fnum)
			}
		}
		resp_incorrect = len(resp_framenum_map)
		log.Println("incorrect num:", incorrect + len(resp_framenum_map))
		log.Println("correct num:", correct)

		log.Println("incorrect request num:", req_incorrect)
		log.Println("correct request num:", req_correct)

		log.Println("incorrect response num:", resp_incorrect)
		log.Println("correct response num:", resp_correct)
		verify_res := verified{Total: total,Correct: correct,Incorrect: incorrect + len(resp_framenum_map) ,Req_correct: req_correct,Req_incorrect: req_incorrect,
			Resp_correct: resp_correct,Resp_incorrect: resp_incorrect}
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

func DecryptMainAnalysis(nameprefix string, cmtest *common.TestSummary) {
	log.Println("DecryptAnalysis")
	//if cmtest != nil {
	kfilename := tsharkutil.Getkeypath(nameprefix)
	if len(kfilename) > 0 {
		var total, correct, incorrect int = 0, 0, 0
		var req_correct, req_incorrect, resp_correct, resp_incorrect int = 0, 0, 0, 0

		streamidmap, streamurimap := tsharkutil.HTTPRequestStream(nameprefix, []string{"downloads", "uploads","hello"})
		for suridx, suri := range streamurimap {
			log.Println("URI in pcap", suridx)
			for _, stmmap := range suri {
				log.Println("--", stmmap.StreamId)
			}
		}
		resp_framenum_map := make(map[int]bool)
		for _, stream := range streamidmap{
			for _, resp := range stream.Response{
				if resp.FrameNum !=0 {
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
				log.Println("stm info: ", u.RequestURI() , stm.Request, stm.Response)

				for _, resp := range stm.Response{
					if flow.PcapInfo.StreamId == stm.StreamId && resp.FrameNum == flow.PcapInfo.Response.FrameNum{
						log.Println("response good match!", u.RequestURI(), 0, flow.NetLogInfo.Method, stm.StreamId, resp.FrameNum, flow.PcapInfo.Response.FrameNum)
						delete(resp_framenum_map, resp.FrameNum)
						correct += 1
						resp_correct +=1
						break
					}
				}
				//log.Println("stm response: ", stm.Response)

				for _, req := range stm.Request {
					if flow.PcapInfo.StreamId == stm.StreamId && req.Method == flow.NetLogInfo.Method && req.Uri == u.RequestURI() {
						if flow.PcapInfo.Request != nil {
							if req.Method == "GET" {
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
							}else if req.Method == "POST" {
								if req.FrameNum == flow.PcapInfo.Request.FrameEnd {
									//correct
									log.Println("request good match!", u.RequestURI(), 0, req.Method, stm.StreamId, req.FrameNum, flow.PcapInfo.Request.FrameNum)
									correct += 1
									req_correct += 1
								} else {
									log.Println("request wrong match!", u.RequestURI(), 0, req.Method, stm.StreamId, req.FrameNum, flow.PcapInfo.Request.FrameNum)
								}

							}
						}
					}

				}

			} else {
				log.Println("URI not exist", u.RequestURI())
			}
		}
		if len(resp_framenum_map) != 0{
			for fnum, _ := range(resp_framenum_map){
				log.Println("response wrong match!", fnum)
			}
		}
		resp_incorrect = len(resp_framenum_map)
		log.Println("incorrect num:", incorrect + len(resp_framenum_map))
		log.Println("correct num:", correct)

		log.Println("incorrect request num:", req_incorrect)
		log.Println("correct request num:", req_correct)

		log.Println("incorrect response num:", resp_incorrect)
		log.Println("correct response num:", resp_correct)
		verify_res := verified{Total: total,Correct: correct,Incorrect: incorrect + len(resp_framenum_map) ,Req_correct: req_correct,Req_incorrect: req_incorrect,
			Resp_correct: resp_correct,Resp_incorrect: resp_incorrect}
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


func RunComcastAnalysis(globwg *sync.WaitGroup, wchan chan int, filepath string, toverify bool) {
	var alldata common.TestSummary
	defer globwg.Done()
	common.Makeplotdir(filepath)
	log.Println("enter")
	if err := savedata.LoadData(savedata.GobName(filepath), &alldata); err != nil {
		alldata = LoadComcast(globwg, wchan, filepath)
	} else {
		log.Println("Found precomputed data")
	}
	if toverify {
		DecryptMainAnalysis(filepath, &alldata)
	}
	//	ComcastPlotRRTime(filepath, alldata.Meta, alldata.Flowmap)
	//	ComcastPlotFlow(filepath, alldata)
	//	ComcastPlotUpload(filepath, alldata)
	<-wchan
}

func ParseComcastURL(u string) (downup int, urls []string) {
	var urlobj []string
	downup = 0
	if urlobj = downloadUrlRegex.FindStringSubmatch(u); urlobj == nil {
		urlobj = uploadUrlRegex.FindStringSubmatch(u)
		if urlobj != nil {
			downup = 1
		}
	}
	if urlobj != nil {
		urlobj[3] = strings.TrimSpace(urlobj[3])
		//log.Println(urlobj)
	}
	return downup, urlobj
}

func ParseComcastURI(u string) (r string) {
	var uriobj []string
	if uriobj = downloadUriRegex.FindStringSubmatch(u); uriobj == nil {
		uriobj = uploadUriRegex.FindStringSubmatch(u)
		if uriobj == nil {
			log.Fatal("URI not match", u)
		}
	}
	return strings.TrimSpace(uriobj[1])
}

func revokeassignment(mflow *common.MeasFlow, restorepck []*tsharkutil.PckSSLInfo) {
	mflow.PcapInfo.StreamId = 0
	mflow.PcapInfo.Request = nil
	mflow.PcapInfo.Response = nil
	mflow.PcapInfo.PckDump = nil
	mflow.SrcPort = ""
	for _, p := range restorepck {
		p.Claimed = false
	}
}

//-1: less than expected, can accept more packets. 0: right on expected. 1: too much data
func compareRange(accdata uint, rangelen, progresslen int, tls_overhead int) int {
	if rangelen == -1 {
		//unknown range, accept anything
		return -1
	}
	var tmp_tls_overhead int
	if rangelen < 1460 && accdata < 1460 {
		//smaller than 1 TCP packet, accept anything that can fit in 1 packet
		return 0
	} else {
		//adjustedrlen := uint((5+24)*progresslen + rangelen)
		if tls_overhead <= 0{
			tmp_tls_overhead = 29
		} else{
			tmp_tls_overhead = tls_overhead
		}
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

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func loadtrace(tracech chan tracelog.PerfLog, metatiming *common.MetaTiming, measflowmap map[string]*common.MeasFlow, randreqidmap map[string][]*common.MeasFlow, cnttimeline []*tracelog.Counters) {
	keys := []int{}
	for _, _ = range randreqidmap {
		keys = append(keys, 1)
	}
	emptyflowmap := (len(keys) == 0)
	for l := range tracech {
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
				downup, urlobj := ParseComcastURL(sndReq.Data.URL)
				randidx := 3
				if downup == 0 {
					randidx = 4
				}
				// urlobj[1] suggests the rcv port of server
				if urlobj != nil {
					if _, exist := measflowmap[sndReq.Data.RequestID]; !exist {
						if emptyflowmap == true {
							//update the rand flow mapping
							found := false
							openoption := ""
							if rmap, rexist := randreqidmap[urlobj[randidx]]; rexist {
								for _, rmapobj := range rmap {
									if rmapobj.Rrs.Method == "OPTIONS" && rmapobj.OptionReqId == "" {
										openoption = rmapobj.ReqId
									}
									if l.Ts-metatiming.Index-rmapobj.XhrTiming.Opened < 1000 {
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
								randreqidmap[urlobj[randidx]] = append(randreqidmap[urlobj[randidx]], newf)
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
							if downup == 0 {
								rlen, _ := strconv.Atoi(urlobj[3])
								measflowmap[sndReq.Data.RequestID].RangeLen = rlen
							}
							measflowmap[sndReq.Data.RequestID].Random = urlobj[randidx]
							measflowmap[sndReq.Data.RequestID].DownUp = downup
							if len(urlobj[2]) > 1 && !contains(hostports, urlobj[2]) {
								hostports = append(hostports, urlobj[2])
							}
							ets := l.Ts - metatiming.Index
							measflowmap[sndReq.Data.RequestID].Rrs = tracelog.FlowDetail{ReqTs: ets, Method: sndReq.Data.RequestMethod, Priority: sndReq.Data.Priority}
							measflowmap[sndReq.Data.RequestID].Rrs.RrsTimeline = append(measflowmap[sndReq.Data.RequestID].Rrs.RrsTimeline, tracelog.Timeline{Ts: ets, Length: 0})
						} else {
							//netlog exists, find and map to existing flows
							if _, uexist := randreqidmap[urlobj[randidx]]; uexist {
								for uidx, randflow := range randreqidmap[urlobj[randidx]] {
									if randflow.ReqId == "" && sndReq.Data.RequestMethod == randflow.NetLogInfo.Method {
										//fill in info from tracing
										randflow.ReqId = sndReq.Data.RequestID
										ets := l.Ts - metatiming.Index
										randflow.Rrs = tracelog.FlowDetail{ReqTs: ets, Method: sndReq.Data.RequestMethod, Priority: sndReq.Data.Priority, RrsTimeline: []tracelog.Timeline{}}
										randflow.Rrs.RrsTimeline = append(randflow.Rrs.RrsTimeline, tracelog.Timeline{Ts: ets, Length: 0})
										measflowmap[sndReq.Data.RequestID] = randreqidmap[urlobj[randidx]][uidx]
										/*if sndReq.Data.RequestMethod == "POST" {
											//look for options
											for u := uidx - 1; u >= 0; u-- {
												if randreqidmap[urlobj[randidx]][u].Rrs.Method == "OPTIONS" && randreqidmap[urlobj[randidx]][u].OptionReqId == "" {
													//open option
													randreqidmap[urlobj[randidx]][u].OptionReqId = sndReq.Data.RequestID
													measflowmap[sndReq.Data.RequestID].OptionReqId = randreqidmap[urlobj[randidx]][u].ReqId
													measflowmap[sndReq.Data.RequestID].XhrTiming = measflowmap[randreqidmap[urlobj[randidx]][u].ReqId].XhrTiming
													break
												}
											}
										}*/
										break
									}

								}
							}
						}
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
				downup, urlobj := ParseComcastURL(xhrData.Data.URL)
				if urlobj != nil {
					randidx := 3
					if downup == 0 {
						randidx = 4
					}
					ets := l.Ts - metatiming.Index
					switch xhrData.Data.ReadyState {
					case 0:
						//UNSENT
						if downup == 0 && metatiming.DownloadStart == 0 {
							metatiming.DownloadStart = ets
						} else if downup == 1 && metatiming.UploadStart == 0 {
							metatiming.UploadStart = ets
						}
						if emptyflowmap {
							if _, exist := randreqidmap[urlobj[randidx]]; !exist {
								//								randreqidmap[urlobj[3]] = &XhrMeta{ReqId: "", Unsent: l.Ts}
								tmp := &common.MeasFlow{}
								tmp.XhrTiming.Unsent = ets
								randreqidmap[urlobj[randidx]] = []*common.MeasFlow{tmp}
							} else {
								log.Println("Dup random:", urlobj[randidx])
							}
						} else {
							for ridx, req := range randreqidmap[urlobj[randidx]] {
								if req.XhrTiming.Unsent == 0 && req.XhrTiming.Opened == 0 {
									randreqidmap[urlobj[randidx]][ridx].XhrTiming.Unsent = ets
								}
							}
						}
					case 1:
						//OPENED
						if downup == 0 && metatiming.DownloadStart == 0 {
							metatiming.DownloadStart = ets
						} else if downup == 1 && metatiming.UploadStart == 0 {
							metatiming.UploadStart = ets
						}
						if _, exist := randreqidmap[urlobj[randidx]]; !exist && emptyflowmap {
							tmp := &common.MeasFlow{}
							tmp.XhrTiming.Unsent = 0
							tmp.XhrTiming.Opened = ets
							randreqidmap[urlobj[randidx]] = []*common.MeasFlow{tmp}
							//								randreqidmap[urlobj[3]] = &XhrMeta{ReqId: "", Unsent: 0, Opened: l.Ts}
						} else {
							if exist {
								var curflow *common.MeasFlow
								for _, tmpflow := range randreqidmap[urlobj[randidx]] {
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
									randreqidmap[urlobj[randidx]] = append(randreqidmap[urlobj[randidx]], tmp)
								}
							}
						}
					case 2:
						//HEADERS_RECEIVED
						if rmap, exist := randreqidmap[urlobj[randidx]]; exist {
							//							var tmpts int64
							//							tmpts = 0
							for _, rurl := range rmap {
								if rurl.XhrTiming.Opened != 0 && rurl.XhrTiming.Header == 0 {
									rurl.XhrTiming.Header = ets


								}
							}
						}
					case 3:
						//LOADING
						if rmap, exist := randreqidmap[urlobj[randidx]]; exist {
							for _, rurl := range rmap {
								if rurl.XhrTiming.Done == 0 && rurl.Rrs.Method != "OPTIONS" {
									rurl.XhrTiming.Loading = append(rurl.XhrTiming.Loading, ets)
								}
							}
						}
					case 4:
						//DONE
						if rmap, exist := randreqidmap[urlobj[randidx]]; exist {
							for _, rurl := range rmap {
								if rurl.XhrTiming.Done == 0 {
									rurl.XhrTiming.Done = ets
								}
							}
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

func loadpcap(fileinfo *common.FilePaths, metatiming *common.MetaTiming, measflowmap map[string]*common.MeasFlow, allmflows []*common.MeasFlow) (map[int]*tsharkutil.RTT_Stream, map[int]*tsharkutil.LostStream, int) {
	its, _ := tsharkutil.DNSQueryTime(fileinfo.Pcap, "speedtest.xfinity.com")
	if its == 0 {
		log.Println("Use HTTPS:", fileinfo.Pcap)
		its = tsharkutil.HTTPSSyncTime(fileinfo.Pcap)
	}
	metatiming.IndexPcap = its
	log.Println("Get DNS host ip")
	if !fileinfo.NetlogExist {
		tsharkutil.DNSHostIP(fileinfo.Pcap, hostipmap)
		log.Println("Get packets")
	}

	////get the stream id of upload/download flows
	//streamidmap, streamurimap := tsharkutil.HTTPRequestStream(filepath, []string{"downloads", "uploads"})
	//streams := []int{}
	//for k, _ := range streamidmap {
	//	streams = append(streams, k)
	//}
	//streams := reflect.ValueOf(streamidmap).MapKeys()
	allsslpcks, allrtts, allpck_lost := tsharkutil.GetSSLStreamsfromIPs(fileinfo.Pcap, hostipmap, hostports)
	//	log.Println(streams)
	//	log.Println("Total no of packets:", len(allsslpcks))
	//	upstream := tsharkutil.HTTPRequestStream(filepath, "uploads")
	//	streamids := []tsharkutil.StreamInfo{}
	//	streamids = append(streamids, dlstream...)
	//streamids = append(streamids, upstream...)

	//get unique stream ids
	streamidmap := make(map[int]*tsharkutil.StreamProgress)
	streamipmap := make(map[string][]*tsharkutil.StreamProgress)
	streamids := []int{}
	var tls_overhead int = -1

	allpcks_len := len(allsslpcks)

	for _, pck := range allsslpcks {
		if _, streamexist := streamidmap[pck.StreamId]; !streamexist {
			streamids = append(streamids, pck.StreamId)
			streamidmap[pck.StreamId] = &tsharkutil.StreamProgress{StreamId: pck.StreamId, PckIndex: 0}
			//assume first packet's dst IP is the measurement server ip
			streamipmap[pck.DstIp] = append(streamipmap[pck.DstIp], streamidmap[pck.StreamId])
		}
	}
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
						if curflow.PcapInfo.Request == nil {
							curflow.PcapInfo.Request = &tsharkutil.HRequest{}
						}
						if curflow.PcapInfo.Request.Ts == 0 {
							//still looking for the http request
							/*							if p.DstIp == mip && strconv.Itoa(p.DstPort) == curflow.Port {
														log.Println("found suspective request: ", p.FrameNo, p.TcpLen, p.SSLRecordType, p.SSL_client_ip, p.SSL_clientstate, p.SSL_serverstate)
													}*/
							if p.TcpLen > 0 && p.SSLRecordType == 23 {
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
									//if download request, calculate tls overhead
									if tls_overhead == -1 {
										var cur_overhead = p.TcpLen - len(curflow.NetLogInfo.RequestHeaderString)
										if cur_overhead >=5 && cur_overhead <= 100{
											tls_overhead = cur_overhead
											log.Println("Get tls overhead: ", tls_overhead)
										}else if cur_overhead <= 0 {
											log.Println("Fake tls overhead && request pkt", cur_overhead)
											curflow.PcapInfo.Request = nil
										}
									}else{
										var cur_overhead = p.TcpLen - len(curflow.NetLogInfo.RequestHeaderString)
										if cur_overhead != tls_overhead{
											log.Println("Found different tls overhead: ", cur_overhead, "old tls overhead is: ",tls_overhead)
											if cur_overhead <= 0{
												log.Println("Fake tls overhead && request pkt", cur_overhead)
												curflow.PcapInfo.Request = nil
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
									} else {
										//only expect GET has multiple response packets
										if curflow.NetLogInfo.Method == "GET" {
											if !respdone {
												//push frameend forward
												curflow.PcapInfo.Response.FrameEnd = p.FrameNo
												currespseq = p.Seq + uint(p.TcpLen)
												switch diff := compareRange(currespseq-startrespseq, curflow.RangeLen, len(curflow.NetLogInfo.Timing.Progress),tls_overhead); {
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
									log.Println("Skip outgoing data", p.FrameNo)
									addpacket = false
								} else {
									if p.TcpLen > 0 && p.SSLRecordType == 23 {
										//handle POST
										if curflow.NetLogInfo.Method == "POST" && !reqdone {
											curreqseq = p.Seq + uint(p.TcpLen)
											if rbyte := compareRange(curreqseq-startreqseq, curflow.RangeLen, len(curflow.NetLogInfo.Timing.Progress)-1,tls_overhead); rbyte >= 0 {
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
