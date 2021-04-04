package fast

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"cloudanalysis/common"
	"cloudanalysis/savedata"
	"cloudanalysis/tracelog"
	"cloudanalysis/tsharkutil"
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

type FastMeasFlow struct {
	Url   string
	Host  string
	Port  string
	ReqId string
	//	Random    string
	OptionReqId string
	SrcPort     string
	DstIp       string
	RangeLen    int
	DownUp      int
	Rrs         tracelog.FlowDetail
	XhrTiming   tracelog.XhrFlow
	PcapInfo    tsharkutil.StreamPcap
}

//create a tmp place before we can see resource request
/*type XhrMeta struct {
	ReqId  string
	Unsent int64
	Opened int64
}*/

type FastMetaTiming struct {
	Index         int64
	IndexPcap     float64
	DownloadStart int64
	DownloadEnd   int64
	UploadStart   int64
	UploadEnd     int64
}

type FastTest struct {
	Meta            *FastMetaTiming
	Flowmap         map[string]*FastMeasFlow
	CounterTimeline []*tracelog.Counters
	pck_num         int
}

//https://ipv4-c002-san001-cenic-isp.1.oca.nflxvideo.net/speedtest/range/0-2048?c=us&n=1909&v=3&e=1539254702&t=ESSDrHLg8Hc77ETajbQT8h223OU
var ProbeUrlRegex = regexp.MustCompile(`^https://(\S+)/speedtest/range/0-(\d+)\?(\S+)`)

//var uploadUrlRegex = regexp.MustCompile(`^http://(\S+)\:(\d+)/api/uploads\?r=([\d\.]+)`)
var ProbeUriRegex = regexp.MustCompile(`^/speedtest/range/(\d+)-(\d+)\?(\S+)`)

//var uploadUriRegex = regexp.MustCompile(`^/api/uploads\?r=([\d\.]+)`)

func LoadFast(globwg *sync.WaitGroup, wchan chan int, filepath string) FastTest {
	//	filepath := `/home/cskpmok/webspeedtestdata/US1/comcast/comcast_1539367807.json`
	log.Println("working on ", filepath)
	msgch := make(chan tracelog.PerfLog)
	go tracelog.ReadLog(filepath, msgch)
	metatiming := FastMetaTiming{}
	measflowmap := make(map[string]*FastMeasFlow)
	//we use the long string as "rand" in fast.com. it is not unique, but it can be used to distinguish measurement servers
	randreqidmap := make(map[string][]*FastMeasFlow)
	hostipmap := make(map[string]string)
	hostports := []string{}
	hostports = append(hostports, "443")
	cnttimeline := []*tracelog.Counters{}
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
				downup, urlobj := ParseFastURL(sndReq.Data.URL)
				if urlobj != nil {
					if _, exist := measflowmap[sndReq.Data.RequestID]; !exist {
						//update the rand flow mapping
						found := false
						urlhash := urlobj[1] + urlobj[2] + urlobj[3]
						openoption := ""
						if rmap, rexist := randreqidmap[urlhash]; rexist {
							for _, rmapobj := range rmap {
								if rmapobj.Rrs.Method == "OPTIONS" && rmapobj.OptionReqId == "" {
									openoption = rmapobj.ReqId
								}
								if l.Ts-metatiming.Index-rmapobj.XhrTiming.Opened < 500000 && rmapobj.ReqId == "" {
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
							newf := &FastMeasFlow{ReqId: sndReq.Data.RequestID}
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
						//standard https port for fast.com
						measflowmap[sndReq.Data.RequestID].Port = "443"

						rnglen, _ := strconv.Atoi(urlobj[2])
						switch sndReq.Data.RequestMethod {
						case "OPTIONS":
							rnglen = 0
							downup = 0
						case "POST":
							downup = 1
						}
						if sndReq.Data.RequestMethod == "OPTIONS" {
							//only one respond packet is expected
							rnglen = 0
						}
						measflowmap[sndReq.Data.RequestID].RangeLen = rnglen
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
				downup, urlobj := ParseFastURL(xhrData.Data.URL)
				if urlobj != nil {
					urlhash := urlobj[1] + urlobj[2] + urlobj[3]
					hostipmap[urlobj[1]] = ""
					ets := l.Ts - metatiming.Index
					switch xhrData.Data.ReadyState {
					case 0:
						if downup == 0 && metatiming.DownloadStart == 0 {
							metatiming.DownloadStart = ets
						} else if downup == 1 && metatiming.UploadStart == 0 {
							//need to fix to determine when the upload test starts
							metatiming.UploadStart = ets
						}
						tmp := &FastMeasFlow{}
						tmp.XhrTiming.Unsent = ets
						if _, exist := randreqidmap[urlhash]; !exist {
							//								randreqidmap[urlobj[3]] = &XhrMeta{ReqId: "", Unsent: l.Ts}
							randreqidmap[urlhash] = []*FastMeasFlow{tmp}
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
							tmp := &FastMeasFlow{}
							tmp.XhrTiming.Unsent = 0
							tmp.XhrTiming.Opened = ets
							randreqidmap[urlhash] = []*FastMeasFlow{tmp}
							//								randreqidmap[urlobj[3]] = &XhrMeta{ReqId: "", Unsent: 0, Opened: l.Ts}
						} else {
							var curflow *FastMeasFlow
							for _, tmpflow := range randreqidmap[urlhash] {
								if tmpflow.XhrTiming.Opened == 0 {
									curflow = tmpflow
									break
								}
							}
							if curflow != nil {
								curflow.XhrTiming.Opened = ets
							} else {
								tmp := &FastMeasFlow{}
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
								if rurl.XhrTiming.Opened != 0 && rurl.XhrTiming.Header == 0 {
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
						}
						/*							for _, rurl := range rmap {
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
							}
						}
						*/
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
	log.Println("Done with Trace.", len(measflowmap))
	for _, mv := range measflowmap {
		log.Println(mv.Url)
		log.Println(mv.ReqId, mv.Rrs.ReqTs, mv.XhrTiming.Opened)
	}
	//get the timestamp of sending the DNS request
	its, _ := tsharkutil.DNSQueryTime(filepath, "fast.com")
	if its == 0 {
		log.Println("Use HTTPS:", filepath)
		its = tsharkutil.HTTPSSyncTime(filepath)
	}
	metatiming.IndexPcap = its
	log.Println("Get DNS host IP")
	tsharkutil.DNSHostIP(filepath, hostipmap)
	log.Println("Get packets")
	allsslpcks,allrtts,allpck_lost := tsharkutil.GetSSLStreamsfromIPs(filepath, hostipmap,hostports)

	//get unique stream ids
	streamidmap := make(map[int]*tsharkutil.StreamProgress)
	streamipmap := make(map[string][]*tsharkutil.StreamProgress)
	streamids := []int{}

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

	//get the stream id of upload/download flows
	//streamidmap, streamurimap := tsharkutil.HTTPRequestStream(filepath, []string{"downloads", "uploads"})
	reqidtail := []int{}
	reqprefix := ""
	for k, _ := range measflowmap {
		rsplit := strings.Split(k, ".")
		reqprefix = rsplit[0]
		rtail, _ := strconv.Atoi(rsplit[1])
		reqidtail = append(reqidtail, rtail)
	}
	sort.Ints(reqidtail)
	for _, ridt := range reqidtail {
		rid := reqprefix + "." + strconv.Itoa(ridt)
		curflow := measflowmap[rid]
		if mip, ipexist := hostipmap[curflow.Host]; ipexist {
			assignedstream := 0
			confirmed := false
			excludeflow := make(map[int]bool)
			accumdatalen := 0
			flowdone := false
			revoke := false
			pendingpck := []*tsharkutil.PckSSLInfo{}
			log.Println("Working on ", rid, curflow.Host, mip, curflow.Rrs.ReqTs, curflow.OptionReqId)

			for pckkey := 0; pckkey < len(allsslpcks); pckkey++ {
				p := allsslpcks[pckkey]
				_, xflow := excludeflow[p.StreamId]
				//flow not exist in excludeflow
				if !xflow {
					ptime := tsharkutil.WithTs(p.Ts-metatiming.IndexPcap, curflow.Rrs.ReqTs, 1000000)
					if assignedstream == 0 && p.DstIp == mip && !p.Claimed && p.TcpLen > 0 && p.SSLRecordType == 23 && !tsharkutil.CheckTcpRstFin(p.Flag) && !excludeflow[p.StreamId] && ptime {
						//&& (curflow.OptionReqId == "" || curflow.Rrs.Method == "OPTIONS")) {
						//|| (curflow.OptionReqId != "" && curflow.Rrs.Method == "POST" && measflowmap[curflow.OptionReqId].PcapInfo.StreamId == p.StreamId && p.FrameNo > measflowmap[curflow.OptionReqId].PcapInfo.Response.FrameNum)) {
						//if assignedstream == 0 && p.DstIp == mip && !p.Claimed && !excludeflow[p.StreamId] && ptime {
						//log.Println("range check:", p.Ts-metatiming.IndexPcap, curflow.Rrs.ReqTs, ptime)
						assignedstream = p.StreamId
						log.Println("flow ", curflow.ReqId, " binds to ", p.StreamId, " frame ", p.FrameNo, curflow.RangeLen, curflow.DownUp, curflow.Rrs.Method)
						/*						if curflow.OptionReqId != "" && curflow.Rrs.Method == "POST" {
												log.Println("starting packet:", measflowmap[curflow.OptionReqId].PcapInfo.Response.FrameNum)
											}*/
						p.Claimed = true
						var req *tsharkutil.HRequest
						resp := &tsharkutil.HResponse{}
						//persistent http request
						if p.TcpLen > 0 && p.SSLRecordType == 23 {
							req = &tsharkutil.HRequest{FrameNum: p.FrameNo, Ts: p.Ts, Method: curflow.Rrs.Method, Uri: ""}
						} else {
							//otherwise it could be a SYN
							req = &tsharkutil.HRequest{}
						}
						pendingpck = append(pendingpck, p)
						curflow.SrcPort = strconv.Itoa(p.SrcPort)
						// add destination to the flow structure.
						curflow.DstIp = p.DstIp
						curflow.PcapInfo = tsharkutil.StreamPcap{StreamId: assignedstream, Request: req, Response: resp, PckDump: []*tsharkutil.PckInfo{p.GetPckInfo()}}

					} else {
						if assignedstream == p.StreamId {
							if curflow.PcapInfo.Request == nil {
								curflow.PcapInfo.Request = &tsharkutil.HRequest{}
							}
							if curflow.PcapInfo.Request.Ts == 0 {
								//still looking for the http request
								if p.TcpLen > 0 && p.SSLRecordType == 23 {
									if p.DstIp == mip {
										log.Println("Found request ", p.FrameNo)
										curflow.PcapInfo.Request.FrameNum = p.FrameNo
										curflow.PcapInfo.Request.Ts = p.Ts
										curflow.PcapInfo.Request.Method = curflow.Rrs.Method
										curflow.PcapInfo.Request.Uri = ""
									} else if p.SrcIp == mip {
										//receive data before request?
										log.Println("Revoke: receive data before request", p.FrameNo)
										revoke = true
									}
								}
							} else {
								//response header
								if curflow.PcapInfo.Response.Ts == 0 {
									if p.SrcIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 && !flowdone {
										curflow.PcapInfo.Response.FrameNum = p.FrameNo
										curflow.PcapInfo.Response.Ts = p.Ts
										log.Println("Found response ", p.FrameNo)
										//download. more packets should come in after header
										if curflow.DownUp == 0 {
											curflow.PcapInfo.Response.FrameEnd = 0
										} else {
											//upload
											//flow not done, check for error
											//	errorpercent := math.Abs(float64(accumdatalen-curflow.RangeLen)) / float64(curflow.RangeLen)
											if !compareRange(accumdatalen, curflow.RangeLen, 0.5) {
												//												if errorpercent > 0.5 {
												log.Println("Revoke: outgoing data does not match at frame", p.FrameNo, accumdatalen, curflow.RangeLen)
												revoke = true
												flowdone = false
											} else {
												//check for next data packet
												flowdone = true
											}
											/*else {
												//log.Println("accept post with low margine", p.FrameNo)
												curflow.PcapInfo.Response.FrameEnd = p.FrameNo
												//confirmed = true
												flowdone = true
											}
											*/
										}
									} else if p.DstIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 && !p.TCPRetrans {
										//got another ongoing data packet, check for POST
										if curflow.DownUp == 1 && curflow.RangeLen > 0 {
											if flowdone {
												revoke = true
												log.Println("Revoke: More than expected outgoing data", p.FrameNo)
											} else {
												if !p.TCPRetrans {
													accumdatalen += p.TcpLen
												}
												if float64(accumdatalen) > float64(curflow.RangeLen)*1.2 && !flowdone {
													if !compareRange(accumdatalen, curflow.RangeLen, 0.5) {
														log.Println("Revoke: outgoing data much larger than range at frame", p.FrameNo, accumdatalen, curflow.RangeLen)
														revoke = true
														flowdone = false
													}
													//log.Println("Upload done:", accumdatalen, curflow.RangeLen, p.FrameNo)
													//													flowdone = true
												}

											}
											//more than expected outgoing, revoke
											/*if flowdone {
												revoke = true
											}*/
										} else {
											log.Println("Revoke: receive unexpected ongoing packet", p.FrameNo)
											revoke = true
											flowdone = false
										}
									}
								} else {
									//we assigned response header. check for violation or adding data packets

									if curflow.DownUp == 0 {
										//download flows. we expect only incoming data packets.
										if p.SrcIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 {
											if !flowdone {
												//download flow. count new packets.
												accumdatalen += p.TcpLen
												//larger than the range parameter in http request
												if float64(accumdatalen) > float64(curflow.RangeLen)*1.2 {
													log.Println("Response ends ", p.FrameNo)
													curflow.PcapInfo.Response.FrameEnd = p.FrameNo
													flowdone = true
												}
											} else {
												log.Println("Revoke: more data than expected", p.FrameNo, accumdatalen, curflow.RangeLen)
												revoke = true
											}
										} else if p.DstIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 {
											if !flowdone {
												if !compareRange(accumdatalen, curflow.RangeLen, 0.5) {
													//outgoing data before reaching expected data length, wrong assignment
													log.Println("Revoke: outgoing data exceed length at frame", p.FrameNo, accumdatalen, curflow.RangeLen)
													revoke = true
													flowdone = false
												} else {
													log.Println("accept with low margin", p.FrameNo)
													curflow.PcapInfo.Response.FrameEnd = curflow.PcapInfo.PckDump[len(curflow.PcapInfo.PckDump)-1].FrameNo
													flowdone = true
													confirmed = true
												}
											} else {
												//start of next request
												confirmed = true
											}
										}
									} else {
										//upload
										if p.SrcIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 {
											//incoming, after we saw the response
											//another incoming packet. wrong flow
											log.Println("Revoke: another incoming packet. wrong flow", p.FrameNo)
											revoke = true
											flowdone = false
										} else if p.DstIp == mip && p.TcpLen > 0 && p.SSLRecordType == 23 {
											//another outgoing
											confirmed = true
										}
									}
								}
								if flowdone && confirmed {
									break
								}
							}
							if pckkey > -1 {
								//just claim all the packets in between
								pendingpck = append(pendingpck, p)
								p.Claimed = true
								curflow.PcapInfo.PckDump = append(curflow.PcapInfo.PckDump, p.GetPckInfo())
							}

							if revoke {
								log.Println("Revoke ", assignedstream)
								excludeflow[assignedstream] = true
								assignedstream = 0
								accumdatalen = 0
								revokeassignment(curflow, pendingpck)
								//do it all over again
								pckkey = -1
								revoke = false
								flowdone = false
								confirmed = false
							}

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
	for rand_id,_:=range measflowmap{
		flow,ok:= measflowmap[rand_id]
		if ok{
			stream_id := flow.PcapInfo.StreamId
			if _,ok := allrtts[stream_id];ok{
				log.Println("meaflow",measflowmap[rand_id].DownUp)
				allrtts[stream_id].Downup = !(measflowmap[rand_id].DownUp==0) //convert int to bool
				allpck_lost[stream_id].Downup = allrtts[stream_id].Downup
				allpck_lost[stream_id].TStart  = allrtts[stream_id].TStart
				allpck_lost[stream_id].TEnd = allrtts[stream_id].TEnd
				//true: up; false: down
			}
		}
	}
	//log.Println(allrtts)


	log.Println("Done with tshark")
	for rid, flow := range measflowmap {
		log.Println(rid, flow.RangeLen, flow.Rrs.Method, len(flow.PcapInfo.PckDump), len(flow.Rrs.RrsTimeline))
	}
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
	//save data
	alldata := FastTest{Meta: &metatiming, Flowmap: measflowmap, CounterTimeline: cnttimeline, pck_num: allpcks_len}
	err := savedata.SaveData(savedata.GobName(filepath), alldata)
	if err != nil {
		log.Fatal(err)
	}

	// save alllosts to json file
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	enc.Encode(allpck_lost)
	paths :=strings.Split(filepath,".")
	lostPath := paths[0]+".lost.json"
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
	RttPath := paths[0]+".rtt.json"
	f1, erro1 := os.OpenFile(RttPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if erro1 != nil {
		log.Println(erro1)
	}

	n1, err1 := io.WriteString(f1, buf.String())
	if err1 != nil {
		log.Println(n1, err1)
	}

	return alldata
}

func RunFastAnalysis(globwg *sync.WaitGroup, wchan chan int, filepath string) {
	var alldata FastTest
	defer globwg.Done()
	common.Makeplotdir(filepath)
	if err := savedata.LoadData(savedata.GobName(filepath), &alldata); err != nil {
		alldata = LoadFast(globwg, wchan, filepath)
	} else {
		log.Println("Found precomputed data")
	}
	FastPlotRRTime(filepath, alldata.Meta, alldata.Flowmap)
	FastPlotFlow(filepath, alldata)
	FastPlotUpload(filepath, alldata)
	<-wchan
}

func ParseFastURL(u string) (downup int, urls []string) {
	var urlobj []string
	downup = 0
	if urlobj = ProbeUrlRegex.FindStringSubmatch(u); urlobj != nil {
		//0-0 are all POST
		if urlobj[2] == "0" {
			downup = 1
		}

		urlobj[3] = strings.TrimSpace(urlobj[3])
		//log.Println(urlobj)
	}
	return downup, urlobj

}

func ParseFastURI(u string) (r string) {
	var uriobj []string
	if uriobj = ProbeUriRegex.FindStringSubmatch(u); uriobj == nil {
		if uriobj == nil {
			log.Fatal("URI not match", u)
		}
	}
	return strings.TrimSpace(uriobj[3])
}

func revokeassignment(mflow *FastMeasFlow, restorepck []*tsharkutil.PckSSLInfo) {
	mflow.PcapInfo.StreamId = 0
	mflow.PcapInfo.Request = nil
	mflow.PcapInfo.Response = nil
	mflow.PcapInfo.PckDump = nil
	mflow.SrcPort = ""
	for _, p := range restorepck {
		p.Claimed = false
	}
}

func compareRange(accdata, rangelen int, errbound float64) bool {
	if rangelen == 0 {
		//smaller than 1 TCP packet
		if accdata < 1460 {
			return true
		}
	} else {
		errp := math.Abs(float64((accdata - rangelen))) / float64(rangelen)
		if errp > errbound {
			return false
		}
	}
	return true
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}