package speedofme

import (
	"bytes"
	"cloudanalysis/common"
	"cloudanalysis/savedata"
	"cloudanalysis/tracelog"
	"cloudanalysis/tsharkutil"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/exp/rand"
)

type SpeedMeasFlow struct {
	Url       string // url name
	Host      string // host ip address
	Port      string // port number (here for host, always same port for dest)
	SrcPort   string
	DstIp     string
	Len       int                   // length of uploaded/downloaded packets
	ReqId     string                // request id
	Random    string                // random number in url
	DownUp    int                   // download: 0; upload: 1
	Rrs       tracelog.FlowDetail   // have no idea for now
	XhrTiming tracelog.XhrFlow      // xhr information
	PcapInfo  tsharkutil.StreamPcap // pcap information associated with the flow
}

type SpeedMetaTiming struct {
	Index         int64   // index: absolute time of the flow in tracedata
	IndexPcap     float64 // have no idea (I guess it is the index in pcap file)
	DownloadStart int64   // start time of download
	DownloadEnd   int64   // end time of download
	UploadStart   int64   // start time of upload
	UploadEnd     int64   // end time of upload
}

type SpeedTest struct {
	Meta            *SpeedMetaTiming
	Flowmap         map[string]*SpeedMeasFlow
	CounterTimeline []*tracelog.Counters
	pck_num         int
}

var preUrlRegex = regexp.MustCompile(`^https://cdn\.speedof\.me/\?r=([\d\.]+)`)
var preUriRegex = regexp.MustCompile(`^/\?r=([\d\.]+)`)
var downloadUrlRegex = regexp.MustCompile(`^https://cdn\.speedof\.me/sample(\S+)k\.bin\?r=([\d\.]+)`)
var uploadUrlRegex = regexp.MustCompile(`^https://cdn\.speedof\.me/post.php`)
var downloadUriRegex = regexp.MustCompile(`^/sample(\S+)\?r=([\d\.]+)`)
var uploadUriRegex = regexp.MustCompile(`^/post\.php`)

// generate a random number used as the request id for upload stream
var upload_rand = rand.Float64()
var upload_req = fmt.Sprintf("%f", upload_rand)

// entry point
func RunSpeedofmeAnalysis(globalwg *sync.WaitGroup, wchan chan int, filepath string) {

	var alldata SpeedTest
	common.Makeplotdir(filepath)
	defer globalwg.Done()
	if err := savedata.LoadData(savedata.GobName(filepath), &alldata); err != nil {
		// load data from json
		log.Println("Not found precomputed data")

		alldata = LoadSpeed(globalwg, wchan, filepath)
	} else {
		//found gob
		log.Println("Found precomputed data")
	}

	SpeedPlotRRTime(filepath, alldata.Meta, alldata.Flowmap)
	SpeedPlotFlow(filepath, alldata)
	SpeedPlotUpload(filepath, alldata)
	<-wchan
}

func LoadSpeed(globalwg *sync.WaitGroup, wchan chan int, filepath string) SpeedTest {

	//	example of filepath
	//  filepath := `/home/cskpmok/webspeedtestdata/US1/comcast/comcast_1539367807.json`

	//create message channel with the data type of perflog
	msgch := make(chan tracelog.PerfLog)
	go tracelog.ReadLog(filepath, msgch)

	//time
	metatiming := SpeedMetaTiming{}

	//map measurement flow to ......
	measflowmap := make(map[string]*SpeedMeasFlow)    // map of requestid to flows
	randreqidmap := make(map[string][]*SpeedMeasFlow) // map of random_request_id in url to flows

	cnttimeline := []*tracelog.Counters{}
	//msgch is the trace entry in json, only those containing ResourceSendRequest and ...... will be presented.
	for l := range msgch {
		switch l.Name {

		case "UpdateCounters":
			//log.Println("UpdateCounters")
			var cnt tracelog.CounterData
			if err := json.Unmarshal(l.Args, &cnt); err == nil {
				// get relative time and append associated jslistener and jsheapsize to cnttimeline;
				ets := l.Ts - metatiming.Index
				counttime := &tracelog.Counters{Ts: ets, Listener: cnt.Data.JsListeners, HeapSize: cnt.Data.JsHeap}
				cnttimeline = append(cnttimeline, counttime)
			}

		case "ResourceSendRequest":
			//log.Println("ResourceSendRequest")
			var sndReq tracelog.RrsRequest
			if err := json.Unmarshal(l.Args, &sndReq); err == nil {
				// parse the associated url of resourcesendrequest, get downup and urlobj;
				// downup: 0 -> download; 1 -> upload
				// urlobj: url
				downup, urlobj := ParseSpeedURL(sndReq.Data.URL)
				if urlobj != nil {
					var found bool

					// why there can be two different formats of requestid? one in jason entry; one in url;
					//		log.Println("ResourceSendRequest", sndReq.Data.RequestID)
					if _, exist := measflowmap[sndReq.Data.RequestID]; !exist {
						//update the rand flow mapping
						found = false
					} else {
						//flow existed?
						log.Println("Dup flow ", sndReq.Data.RequestID)
					}
					//urlobj[2] indicates the requestid in url if download
					//check whether the the reaquest with request id = urlobj[2] exists in randreqidmap
					urlhash := ""
					if downup == 0 || downup == 2 {
						if len(urlobj) >= 3 {
							urlhash = urlobj[2]
						} else {
							urlhash = urlobj[1]
						}
					} else {
						urlhash = "POST"
					}
					openoption := ""
					if rmap, rexist := randreqidmap[urlhash]; rexist {
						for _, rmapobj := range rmap {
							if l.Ts-metatiming.Index-rmapobj.XhrTiming.Opened < 1000 {
								measflowmap[sndReq.Data.RequestID] = rmapobj
								measflowmap[sndReq.Data.RequestID].ReqId = sndReq.Data.RequestID
								if rmapobj.Rrs.Method == "OPTIONS" {
									measflowmap[sndReq.Data.RequestID].DownUp = -1
								}
								found = true
								break
							}
							if rmapobj.Rrs.Method == "OPTIONS" && rmapobj.Rrs.BindedReq == "" {
								openoption = rmapobj.ReqId
							}
						}
					}

					if !found {
						// new flow
						newf := &SpeedMeasFlow{ReqId: sndReq.Data.RequestID}
						measflowmap[sndReq.Data.RequestID] = newf
						randreqidmap[urlhash] = append(randreqidmap[urlhash], newf)
					}

					//create a flow record
					measflowmap[sndReq.Data.RequestID].Url = urlobj[0]
					if downup == 0 {
						if len(urlobj) >= 3 {
							measflowmap[sndReq.Data.RequestID].Len, _ = strconv.Atoi(urlobj[1])
							//measflowmap[sndReq.Data.RequestID].Len = measflowmap[sndReq.Data.RequestID].Len*1024
							measflowmap[sndReq.Data.RequestID].Random = urlobj[2]
						} else {
							measflowmap[sndReq.Data.RequestID].Len = -1 //unknown
							measflowmap[sndReq.Data.RequestID].Random = urlobj[1]
						}
					} else {
						measflowmap[sndReq.Data.RequestID].Random = "POST"
					}
					//} else{
					//	measflowmap[sndReq.Data.RequestID].Len, _ = strconv.Atoi(urlobj[1])
					//measflowmap[sndReq.Data.RequestID].Len = measflowmap[sndReq.Data.RequestID].Len*1024
					//measflowmap[sndReq.Data.RequestID].Random = urlobj[2]
					//}

					measflowmap[sndReq.Data.RequestID].DownUp = downup
					measflowmap[sndReq.Data.RequestID].Rrs = tracelog.FlowDetail{ReqTs: l.Ts - metatiming.Index, Method: sndReq.Data.RequestMethod, Priority: sndReq.Data.Priority, BindedReq: ""}
					if openoption != "" {
						measflowmap[openoption].Rrs.BindedReq = sndReq.Data.RequestID
						measflowmap[sndReq.Data.RequestID].XhrTiming = measflowmap[openoption].XhrTiming
					}
				}
			}

		case "ResourceReceiveResponse":
			//log.Println("ResourceReceiveResponse")
			var rcvRsp tracelog.RrsRecvResp
			if err := json.Unmarshal(l.Args, &rcvRsp); err == nil {
				rid := rcvRsp.Data.RequestID
				ets := l.Ts - metatiming.Index
				if _, exist := measflowmap[rid]; exist {

					measflowmap[rid].Rrs.RespTs = ets
					measflowmap[rid].Rrs.StatusCode = rcvRsp.Data.StatusCode
					measflowmap[rid].Rrs.Timing = rcvRsp.Data.Timing
					// in resourcereceiveresponse, the encodeddatalength is approximately arount 480, why download ends here?
					measflowmap[rid].Rrs.RrsTimeline = append(measflowmap[rid].Rrs.RrsTimeline, tracelog.Timeline{Ts: ets, Length: rcvRsp.Data.EncodedDataLength})

				}
			}
		case "ResourceReceivedData":
			//log.Println("ResourceReceivedData")
			var rcvData tracelog.RrsRcvData
			ets := l.Ts - metatiming.Index
			if err := json.Unmarshal(l.Args, &rcvData); err == nil {
				rid := rcvData.Data.RequestID
				if _, exist := measflowmap[rid]; exist {
					//log.Println("Match ", rid, rcvData.Data.EncodedDataLength)
					measflowmap[rid].Rrs.RrsTimeline = append(measflowmap[rid].Rrs.RrsTimeline, tracelog.Timeline{Ts: l.Ts - metatiming.Index, Length: rcvData.Data.EncodedDataLength})
				} else {
					//log.Println("Not match ", rid)
				}
				if _, exist := measflowmap[rid]; exist {
					if measflowmap[rid].DownUp == 0 {
						metatiming.DownloadEnd = ets
					} else {
						metatiming.UploadEnd = ets
					}
				}

			}

		case "XHRReadyStateChange":
			//log.Println("XHRReadyStateChange")
			var xhrData tracelog.XhrReady
			if err := json.Unmarshal(l.Args, &xhrData); err == nil {
				downup, urlobj := ParseSpeedURL(xhrData.Data.URL)
				if urlobj != nil {
					ets := l.Ts - metatiming.Index
					urlhash := ""
					if downup == 0 {
						if len(urlobj) >= 3 {
							urlhash = urlobj[2]
						} else {
							urlhash = urlobj[1]
						}
					} else if downup == 1 {
						urlhash = "POST"
					}
					switch xhrData.Data.ReadyState {

					case 0: //UNSENT
						if downup == 0 && metatiming.DownloadStart == 0 {
							metatiming.DownloadStart = ets
						} else if downup == 1 && metatiming.UploadStart == 0 {
							metatiming.UploadStart = ets
						}
						if _, exist := randreqidmap[urlhash]; !exist {
							//								randreqidmap[urlobj[3]] = &XhrMeta{ReqId: "", Unsent: l.Ts}
							tmp := &SpeedMeasFlow{}
							tmp.XhrTiming.Unsent = ets
							randreqidmap[urlhash] = []*SpeedMeasFlow{tmp}
						} else {
							log.Println("Dup random:", urlobj[2])
						}

					case 1: //OPENED
						if downup == 0 && metatiming.DownloadStart == 0 {
							metatiming.DownloadStart = ets
						} else if downup == 1 && metatiming.UploadStart == 0 {
							metatiming.UploadStart = ets
						}

						if _, exist := randreqidmap[urlhash]; !exist {
							tmp := &SpeedMeasFlow{}
							tmp.XhrTiming.Unsent = 0
							tmp.XhrTiming.Opened = ets
							//upload flow has no random number
							randreqidmap[urlhash] = []*SpeedMeasFlow{tmp}
							//								randreqidmap[urlobj[3]] = &XhrMeta{ReqId: "", Unsent: 0, Opened: l.Ts}
						} else {
							var curflow *SpeedMeasFlow
							for _, tmpflow := range randreqidmap[urlhash] {
								if tmpflow.XhrTiming.Opened == 0 {
									curflow = tmpflow
									break
								}
							}
							if curflow != nil {
								log.Println("Set opened for", curflow.ReqId)
								curflow.XhrTiming.Opened = ets
							} else {
								tmp := &SpeedMeasFlow{}
								tmp.XhrTiming.Unsent = 0
								tmp.XhrTiming.Opened = ets
								randreqidmap[urlhash] = append(randreqidmap[urlhash], tmp)
							}
						}
					case 2: //HEADERS_RECEIVED
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
					case 3: //LOADING
						if rmap, exist := randreqidmap[urlhash]; exist {
							for _, rurl := range rmap {
								if rurl.XhrTiming.Done == 0 && rurl.Rrs.Method != "OPTIONS" {
									rurl.XhrTiming.Loading = append(rurl.XhrTiming.Loading, ets)
								}
							}
						}
					case 4: //DONE
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
			//log.Println("navigationStart")
			if metatiming.Index == 0 {
				metatiming.Index = l.Ts
			}
		}
	}
	log.Println("Done with Trace.", len(measflowmap))
	/////////////////////////////////////////////////////////////////////////////////
	//pcap
	/////////////////////////////////////////////////////////////////////////////////

	//get the timestamp of sending the DNS request
	its, _ := tsharkutil.DNSQueryTime(filepath, "speedof.me")
	if its == 0 {
		log.Println("Use HTTPS:", filepath)
		its = tsharkutil.HTTPSSyncTime(filepath)
	}
	log.Println("dns time", its)
	metatiming.IndexPcap = its

	//ricky mod starts here
	_, hstrsrcport, hdstip := tsharkutil.FindHeaviestFlow(filepath)
	hsrcport, _ := strconv.Atoi(hstrsrcport)
	log.Println("Heaviest flow", hsrcport)
	hostipmap := make(map[string]string)
	hostipmap["cdn.speedof.me"] = hdstip
	hostposts := []string{}
	hostposts = append(hostposts, "443")

	allsslpcks, allrtts, allpck_lost := tsharkutil.GetSSLStreamsfromIPs(filepath, hostipmap, hostposts)
	reqidtail := []int{}
	reqprefix := ""
	for k, _ := range measflowmap {
		rsplit := strings.Split(k, ".")
		reqprefix = rsplit[0]
		rtail, _ := strconv.Atoi(rsplit[1])
		reqidtail = append(reqidtail, rtail)
	}
	sort.Ints(reqidtail)
	//	processedheads := 0
	//	processedgets := 0
	processedposts := 0

	//	upload_count := []int{8192 * 1024, 16384 * 1024, 32768 * 1024, 65536 * 1024, 131072 * 1024}
	initpckkey := 0
	httpth := 70
	//pendingoption := 0
	for _, ridt := range reqidtail {
		rid := reqprefix + "." + strconv.Itoa(ridt)
		curflow := measflowmap[rid]
		curflow.Port = "443"
		revoke := false
		pendingpck := []*tsharkutil.PckSSLInfo{}
		accumdatalen := 0
		flowdone := false
		confirm := false
		//OPTION
		/*		if curflow.Rrs.Method == "OPTIONS" {
					//			log.Println("Found option", ridt)
					pendingoption = ridt
					continue
				}
				//POST and has pending options, transfer XHR timing of option to post
				if curflow.DownUp == 1 && pendingoption > 0 {
					pid := reqprefix + "." + strconv.Itoa(pendingoption)
					measflowmap[rid].XhrTiming = measflowmap[pid].XhrTiming
					log.Println("Patching", rid, pid, measflowmap[rid].XhrTiming, measflowmap[pid].XhrTiming)
					pendingoption = 0
				}*/
		if curflow.DownUp == 2 {
			//simply skip the first GET which does not belong to the measurement flow
			continue
		} else {
			log.Println("Working on", rid, curflow.Url, curflow.Rrs.Method, allsslpcks[initpckkey].FrameNo)
			for pckkey := initpckkey; pckkey < len(allsslpcks) && !flowdone; pckkey++ {
				p := allsslpcks[pckkey]
				//match heaviest flow, and outgoing
				/*				if p.SrcPort == hsrcport {
								log.Println(p.FrameNo, p.TcpLen, p.SSLRecordType)
							}*/
				if p.SrcPort == hsrcport && !p.Claimed && p.TcpLen > 0 && p.SSLRecordType == 23 {
					//no pcapinfo about this flow, look for request
					if curflow.PcapInfo.Request == nil {
						ptime := tsharkutil.WithTs(p.Ts-metatiming.IndexPcap, curflow.Rrs.ReqTs, 5000000)
						log.Println("looking for request", p.FrameNo, p.Ts, p.Ts-metatiming.IndexPcap, curflow.Rrs.ReqTs, p.SSLRecordType, ptime)
						//hardcode the request legnth must >70 bytes
						if !p.Claimed && p.TcpLen > httpth && p.SSLRecordType == 23 {
							log.Println("Set request", p.FrameNo)
							req := &tsharkutil.HRequest{FrameNum: p.FrameNo, Ts: p.Ts, Method: curflow.Rrs.Method, Uri: ""}
							curflow.PcapInfo = tsharkutil.StreamPcap{StreamId: p.StreamId, Request: req, Response: &tsharkutil.HResponse{}, PckDump: []*tsharkutil.PckInfo{p.GetPckInfo()}}
							curflow.SrcPort = strconv.Itoa(p.SrcPort)
							curflow.DstIp = p.DstIp
						}
					} else {
						//saw another outgoing data packet
						//						if !p.Claimed && p.TcpLen > 0 && p.SSLRecordType == 23 {
						switch curflow.Rrs.Method {
						case "HEAD", "OPTIONS":
							//expect a response packet, revoke
							revoke = true
						case "GET":
							if p.TcpLen > httpth {
								errorpercent := math.Abs(float64(accumdatalen-curflow.Len*1024)) / float64(curflow.Len*1024)
								if errorpercent > 0.5 {
									log.Println("Expect ", curflow.Len*1024, "Now have", accumdatalen)
									revoke = true
								} else {
									flowdone = true
									confirm = true
								}
							}
						case "POST":
							accumdatalen += p.TcpLen
						}
						//						}
					}
				} else if p.DstPort == hsrcport && !p.Claimed && p.TcpLen > 0 && p.SSLRecordType == 23 && curflow.PcapInfo.StreamId != 0 { //incoming
					switch curflow.Rrs.Method {
					case "HEAD", "OPTIONS":
						//expect the incoming packet ACKs the request data packet
						if curflow.PcapInfo.Request != nil {
							reqpck := curflow.PcapInfo.PckDump[0]
							//							log.Println("Response check:", p.Ack, reqpck.Seq, reqpck.TcpLen)
							if p.Ack == reqpck.Seq+uint(reqpck.TcpLen) {
								//match TCP
								curflow.PcapInfo.Response.FrameNum = p.FrameNo
								curflow.PcapInfo.Response.Ts = p.Ts
								curflow.PcapInfo.Response.FrameEnd = p.FrameNo // expect only 1 packet
								flowdone = true

							} else {
								revoke = true
							}
						}
					case "GET":
						if curflow.PcapInfo.Response.Ts == 0 {
							curflow.PcapInfo.Response.FrameNum = p.FrameNo
							curflow.PcapInfo.Response.Ts = p.Ts
						}
						curflow.PcapInfo.Response.FrameEnd = p.FrameNo // expect only 1 packet
						accumdatalen += p.TcpLen
						//			log.Println("Check incoming", p.FrameNo, accumdatalen)
					case "POST":
						if p.TcpLen > httpth && curflow.PcapInfo.Request != nil {
							//							log.Println("Incoming data", curflow.PcapInfo.Request)
							//							errorpercent := math.Abs(float64(accumdatalen-upload_count[processedposts]) / float64(upload_count[processedposts]))
							//							if errorpercent > 0.5 {
							//	log.Println("Expect ", upload_count[processedposts], "Now have", accumdatalen)
							//								revoke = true
							//							} else {
							log.Println("Response:", p.FrameNo)
							processedposts += 1
							flowdone = true
							curflow.PcapInfo.Response.FrameNum = p.FrameNo
							curflow.PcapInfo.Response.Ts = p.Ts
							curflow.PcapInfo.Response.FrameEnd = p.FrameNo // expect only 1 packet
							//							}
						}
						//else {
						//	log.Println("Extra incoming before Request")
						//}
					}

				}
				if !revoke && curflow.PcapInfo.Request != nil && !confirm {
					p.Claimed = true
					curflow.PcapInfo.PckDump = append(curflow.PcapInfo.PckDump, p.GetPckInfo())
					pendingpck = append(pendingpck, p)
				}
				if flowdone {
					initpckkey = pckkey
				}
				if revoke {
					log.Println("Revoke", rid, p.FrameNo)
					accumdatalen = 0
					initpckkey = pckkey //start from this packet
					pckkey -= 1
					revoke = false
					confirm = false
					flowdone = false
					revokeassignment(curflow, pendingpck)
				}
			}
			if !flowdone {
				log.Println("Cannot assign packet to flow", rid)
			}
		}
	}
	//ricky mod ends here
	/*
		Download_num := 0
		for _, m := range measflowmap {
			log.Println(m.Url, m.Len, m.XhrTiming)
			if m.DownUp == 0 {
				Download_num++
			}
		}

		//get the stream id of upload/download flows

		streamidmap, allstreampcks, pck_num := tsharkutil.HTTPSStream(filepath, Download_num)
		for _, a := range allstreampcks {
			log.Println("first pack in each stream")
			log.Println(a[0])

		}

		//streamidmap, streamurimap := tsharkutil.HTTPRequestStream(filepath, []string{"downloads", "uploads"})
		streams := []int{}
		for k, _ := range streamidmap {
			streams = append(streams, k)
		}

		log.Println(streams)
		log.Println("Total number of streams:", len(allstreampcks))

		//	upstream := tsharkutil.HTTPRequestStream(filepath, "uploads")
		//	streamids := []tsharkutil.StreamInfo{}
		//	streamids = append(streamids, dlstream...)
		//streamids = append(streamids, upstream...)

		//	log.Println(len(dlstream), len(upstream), len(streamids))
		//	log.Println(streamids)
		//var wg sync.WaitGroup

		//
		//var wg sync.WaitGroup
		workers := make(chan int, 1)

		type sortmap struct {
			request_id string
			Length     int
			Downup     int
		}
		keys := make([]sortmap, 0)

		for request_id, k := range measflowmap {
			if k.Rrs.Method == "OPTIONS" {
				k.DownUp = +100

			}
			keys = append(keys, sortmap{request_id, k.Len, k.DownUp})
		}

		sort.Slice(keys, func(i, j int) bool {
			if keys[i].Downup < keys[j].Downup {
				return true
			}
			if keys[i].Downup > keys[j].Downup {
				return false
			}
			if keys[i].Downup == 0 {
				return keys[i].request_id < keys[j].request_id
			} else {
				return keys[i].Length < keys[j].Length

			}

		})
		log.Println("down with sorting measmap", keys)
		for index, flow_key := range keys {
			log.Println(index)
			mflow := measflowmap[flow_key.request_id]
			workers <- 1
			if _, err := streamidmap[index]; err {
				if streamidmap[index].StreamLen > 0 {
					mflow.Port = strconv.Itoa(allstreampcks[index][0].DstPort)
					mflow.SrcPort = strconv.Itoa(allstreampcks[index][0].SrcPort)
					mflow.DstIp = allstreampcks[index][0].DstIp
					mflow.Host = mflow.DstIp
					mflow.PcapInfo.StreamId = index
					mflow.PcapInfo.Request = &streamidmap[index].Request[0]
					mflow.PcapInfo.Response = &streamidmap[index].Response[0]
					//				log.Println("Request:", mflow.PcapInfo.Request)

					mflow.PcapInfo.PckDump = allstreampcks[index]
				}
			}

			<-workers
		}
	*/
	//wait until all go routine finished
	//allocate downup to allrtts
	for rand_id, _ := range measflowmap {
		flow, ok := measflowmap[rand_id]
		if ok {
			stream_id := flow.PcapInfo.StreamId
			if _, ok := allrtts[stream_id]; ok {
				log.Println("meaflow", measflowmap[rand_id].DownUp)
				allrtts[stream_id].Downup = !(measflowmap[rand_id].DownUp == 0) //convert int to bool
				allpck_lost[stream_id].Downup = allrtts[stream_id].Downup
				allpck_lost[stream_id].TStart = allrtts[stream_id].TStart
				allpck_lost[stream_id].TEnd = allrtts[stream_id].TEnd
				//true: up; false: down
			}
		}
	}
	//log.Println(allrtts)

	log.Println("Done with tshark")
	for _, m := range measflowmap {

		log.Println(m.Url, m.Len, m.DownUp, m.ReqId, len(m.PcapInfo.PckDump), m.PcapInfo.Request, m.PcapInfo.Response, m.XhrTiming)
	}

	//save data
	//	alldata := SpeedTest{Meta: &metatiming, Flowmap: measflowmap, CounterTimeline: cnttimeline, pck_num: pck_num}
	alldata := SpeedTest{Meta: &metatiming, Flowmap: measflowmap}
	err := savedata.SaveData(savedata.GobName(filepath), alldata)
	if err != nil {
		log.Fatal(err)
	}

	// save alllosts to json file
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

	return alldata
	//	log.Println(metatiming)
}

// used to parse the url of comcast
func ParseSpeedURL(u string) (downup int, urls []string) {
	var urlobj []string
	downup = 0 // default to be download
	if urlobj = downloadUrlRegex.FindStringSubmatch(u); urlobj == nil {
		urlobj = uploadUrlRegex.FindStringSubmatch(u) // return the substring in u which holds the text of the leftmost match of the regular expression.
		if urlobj != nil {

			downup = 1 //upload

			//log.Println(upload_req)
			//urlobj = append(urlobj, "8192") //upload size: 8192k
			//urlobj = append(urlobj, upload_req)

		} else {
			downup = 2 //head
			urlobj = preUrlRegex.FindStringSubmatch(u)
		}
	}
	//if urlobj != nil {  //download
	//	urlobj[2] = strings.TrimSpace(urlobj[2]) //get rid of space
	//	log.Println(urlobj)
	//}
	return downup, urlobj
}

func ParseSpeedURI(u string) (r string) {
	var uriobj []string
	if uriobj = downloadUriRegex.FindStringSubmatch(u); uriobj == nil {
		uriobj = uploadUriRegex.FindStringSubmatch(u)
		if uriobj == nil {
			uriobj = preUriRegex.FindStringSubmatch(u)
			if uriobj == nil {
				log.Fatal("URI not match", u)
			}
		}
	}
	return strings.TrimSpace(uriobj[1])
}

func revokeassignment(mflow *SpeedMeasFlow, restorepck []*tsharkutil.PckSSLInfo) {
	mflow.PcapInfo.StreamId = 0
	mflow.PcapInfo.Request = nil
	mflow.PcapInfo.Response = nil
	mflow.PcapInfo.PckDump = nil
	for _, p := range restorepck {
		p.Claimed = false
	}
}
