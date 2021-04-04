package netlog

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type SSource struct {
	Id           int    `json:"id"`
	StartTimeRaw string `json:"start_time"`
	StartTime    int64  `json:"-"`
	Type         int    `json:"type"`
}

type ParamsRequest struct {
	Initiator string `json:"initiator"`
	LoadFlag  int    `json:"load_flag"`
	Method    string `json:"method"`
	Url       string `json:"url"`
}

type ParamsInit struct {
	Priority          string `json:"priority"`
	TrafficAnnotation int    `json:"traffic_annotation"`
	Url               string `json:"url"`
}
type SSrcDep struct {
	Id   int `json:"id"`
	Type int `json:"type"`
}

type ParamsSrcDep struct {
	SrcDep SSrcDep `json:"source_dependency"`
}

//for both requests/responses
type ParamsHTTP struct {
	Headers []string `json:"headers"`
	Request string   `json:"line"`
}

//for download progress, type: 111
type ParamsByteCnt struct {
	ByteCount int64 `json:"byte_count"`
}

//for upload progress, type: 410
type ParamsCurPos struct {
	CurrentPosition int64 `json:"current_position"`
}

type ParamsPOST struct {
	Merge  bool  `json:"did_merge"`
	Chunk  bool  `json:"is_chunked"`
	Length int64 `json:"length"`
}

type ParamsDstAddr struct {
	Addr string `json:"address"`
}
type ParamsSrcAddr struct {
	SrcAddr string `json:"source_address"`
}

type Netlog struct {
	TimeRaw string      `json:"time"`
	Ts      int64       `json:"-"`
	Type    int         `json:"type"`
	Source  SSource     `json:"source"`
	Phase   int         `json:"phase"`
	Param   interface{} `json:"params"`
}

type InitData struct {
	Constant struct {
		Ts int64 `json:"timeTickOffset"`
		// AddrFamMap map[string]int `json:"addressFamily"` 
		// CertFlagMap map[string]int `json:"certStatusFlag"`
		// CertVerMao map[string]int `json:"certVerifierFlags"`
		// ClientInfoMap map[string]int `json:"clientInfo"`
		// LoadFlagMap map[string]int `json:"loadFlag"`
		// LoadStaMap map[string]int `json:"loadState"`
		// EvtPhaMap map[string]int `json:"logEventPhase"`
		EvtTypeMap map[string]int `json:"logEventTypes"`
		// LevelTypeMap map[string]int `json:"logLevelType"`
 
		// SrcTypeMap map[string]int `json:"logSourceType"`
		// NetErrMap map[string]int `json:"netError"`
		// NetInfoSrcMap map[string]int `json:"netInfoSources"`
		// QuicErrMap map[string]int `json:"quicError"`
		// QuicRstErrMap map[string]int `json:"quicRstStreamError"`
	} `json:"constants"`
}

type SProgress struct {
	Ts         int64
	LoadedByte int64
}

type SEvent struct {
	Ts   int64
	Type int
}

type NetLogTiming struct {
	StartTs          int64
	UrlRequestStart  []SEvent    //type100, 164, 169
	HttpStreamJobCtr []SEvent    //type 155,25,144
	HttpStream       []SEvent    //type 143,150
	Progress         []SProgress //processed value of type 111 and 410
}

type SocketFlow struct {
	DstIP   string
	SrcIP   string
	DstPort string
	SrcPort string
	FlowEvt []int
}

type FlowNetLog struct {
	Url            string
	Method         string
	FlowDetails    *SocketFlow
	ContentLength  int64 //not necessarily available
	RequestHeader  []string
	ResponseHeader []string
	EvtIds         []int
	Timing         NetLogTiming
	RequestHeaderString string
}
type NetLogRecord struct {
	StartUnixTs int64 //Unix timestamp of the very first record
	StartTs     int64 //The corresponding log timestamp in the first record
	IndexTs     int64 // The log timestamp of requesting the index page
	Flows       []*FlowNetLog
}



func LoadNetLog(filename string, indexpageurl string, routes []string) *NetLogRecord {
	//assume it is not a complete json, parse line by line
	log.Println("Load netlog", filename)
	nlogf, err := os.Open(filename)
	defer nlogf.Close()
	if err != nil {
		log.Panic("LoadNetLog error", filename, err)
		return nil
	}
	netlogrec := &NetLogRecord{StartUnixTs: 0, StartTs: 0, IndexTs: 0, Flows: []*FlowNetLog{}}

	flowidmap := make(map[int]*FlowNetLog)
	socketmap := make(map[int]*SocketFlow)
	nettypemap := make(map[int]string)

	firstline := true
	scanner := bufio.NewScanner(nlogf)

	//content_length regx and address regx
	clenregx := regexp.MustCompile(`Content-Length: (\d+)`)
	addrregx := regexp.MustCompile(`(\S+):(\d+)$`)

	for scanner.Scan() {
		//cut the comma at the end
		linestr := strings.Trim(scanner.Text(), ",\n")
		if firstline == true {
			//record the mappings between log types and specific numbers. 
			firstline = false
			linestr = linestr + "}"
			constdata := InitData{}
			if err := json.Unmarshal([]byte(linestr), &constdata); err == nil {
				for evt_type,type_num := range constdata.Constant.EvtTypeMap {
					nettypemap[type_num] = evt_type
				}
			}else{
				log.Panic("Netlog initdata error", err)

			}
			netlogrec.StartUnixTs = constdata.Constant.Ts
			continue
		}
		//jsonl starts and ends with {}
		if string(linestr[0]) == "{" && string(linestr[len(linestr)-1]) == "}" {
			netdata := Netlog{}
			if err := json.Unmarshal([]byte(linestr), &netdata); err == nil {
				netdata.Ts, err = strconv.ParseInt(netdata.TimeRaw, 10, 64)
				curTs := netdata.Ts - netlogrec.IndexTs
				if err != nil {
					log.Println("Bad timestamp", linestr)
					continue
				}

				if net_evttype,ok := nettypemap[netdata.Type]; ok{
					switch net_evttype {
					case "COOKIE_STORE_ALIVE":
						if netlogrec.StartTs == 0 {
							netlogrec.StartTs = netdata.Ts
						}
					case "REQUEST_ALIVE":
						initparam, _ := json.Marshal(netdata.Param)
						pinit := ParamsInit{}
						_ = json.Unmarshal(initparam, &pinit)
						if pinit.Url == indexpageurl && netlogrec.IndexTs == 0 {
							netlogrec.IndexTs = netdata.Ts
						}
					case "URL_REQUEST_START_JOB":
						//new request, init data structure
						if netdata.Source.Id != 0 {
							if _, fexist := flowidmap[netdata.Source.Id]; !fexist {
								//parse the parameter
								mapparam, _ := json.Marshal(netdata.Param)
								reqobj := ParamsRequest{}
								_ = json.Unmarshal(mapparam, &reqobj)
								newflow := &FlowNetLog{}
								urlcheck := false

								for _, route := range routes {
									if strings.Contains(reqobj.Url, route) {
										// "download or upload in the url", is a measurement flow request
										urlcheck = true
										break
									}
								}
								if urlcheck || len(routes) == 0 {
									newflow.Url = reqobj.Url
									newflow.Method = reqobj.Method
									newflow.RequestHeader = []string{}
									newflow.ResponseHeader = []string{}
									newflow.ContentLength = -1
									newflow.Timing.StartTs = curTs
									newevt := SEvent{Ts: curTs, Type: netdata.Type}
									newflow.Timing.UrlRequestStart = []SEvent{newevt}
									newflow.Timing.HttpStreamJobCtr = []SEvent{}
									newflow.Timing.HttpStream = []SEvent{}
									newflow.Timing.Progress = []SProgress{}
									newflow.EvtIds = []int{netdata.Source.Id}
									flowidmap[netdata.Source.Id] = newflow
								}
							}
						}
					case "SOCKET_POOL_BOUND_TO_CONNECT_JOB", "HTTP_STREAM_JOB_CONTROLLER_BOUND", "HTTP_STREAM_REQUEST_BOUND_TO_JOB":
						//attach events to the main event
						if _, fexist := flowidmap[netdata.Source.Id]; netdata.Source.Id > 0 && fexist {
							srcdep, _ := json.Marshal(netdata.Param)
							srcdepobj := ParamsSrcDep{}
							_ = json.Unmarshal(srcdep, &srcdepobj)
							if _, bexist := flowidmap[srcdepobj.SrcDep.Id]; !bexist {
								flowidmap[srcdepobj.SrcDep.Id] = flowidmap[netdata.Source.Id]
								flowidmap[netdata.Source.Id].EvtIds = append(flowidmap[netdata.Source.Id].EvtIds, srcdepobj.SrcDep.Id)
							}
						}
					case "TCP_CONNECT":
						//phase 2:source_address
						if _, fexist := socketmap[netdata.Source.Id]; netdata.Source.Id > 0 && netdata.Phase == 2 {
							if !fexist {
								socketmap[netdata.Source.Id] = &SocketFlow{}
								socketmap[netdata.Source.Id].FlowEvt = []int{}
							}
							srcparam, _ := json.Marshal(netdata.Param)
							srcobj := ParamsSrcAddr{}
							_ = json.Unmarshal(srcparam, &srcobj)
							iparr := addrregx.FindStringSubmatch(srcobj.SrcAddr)
							if len(iparr) == 3 {
								socketmap[netdata.Source.Id].SrcIP = iparr[1]
								socketmap[netdata.Source.Id].SrcPort = iparr[2]
							} else {
								log.Println("malform address and port", srcobj.SrcAddr)
							}
						}
					case "TCP_CONNECT_ATTEMPT":
						//dst addr
						if _, fexist := socketmap[netdata.Source.Id]; netdata.Source.Id > 0 {
							if !fexist {
								socketmap[netdata.Source.Id] = &SocketFlow{}
								socketmap[netdata.Source.Id].FlowEvt = []int{}
							}
							dstparam, _ := json.Marshal(netdata.Param)
							dstobj := ParamsDstAddr{}
							_ = json.Unmarshal(dstparam, &dstobj)
							iparr := addrregx.FindStringSubmatch(dstobj.Addr)
							if len(iparr) == 3 {
								socketmap[netdata.Source.Id].DstIP = iparr[1]
								socketmap[netdata.Source.Id].DstPort = iparr[2]
							}
						} else {
							log.Println("Socket not exist", netdata.Source.Id)
						}
					case "SOCKET_ALIVE", "SOCKET_IN_USE", "SOCKET_POOL_BOUND_TO_SOCKET":
						//attach SSL event to main event
						srcdep, _ := json.Marshal(netdata.Param)
						srcdepobj := ParamsSrcDep{}
						_ = json.Unmarshal(srcdep, &srcdepobj)
						if _, fexist := flowidmap[srcdepobj.SrcDep.Id]; srcdepobj.SrcDep.Id > 0 && fexist {
							if _, sexist := socketmap[netdata.Source.Id]; netdata.Source.Id > 0 && !sexist {
								socketmap[netdata.Source.Id] = &SocketFlow{}
								socketmap[netdata.Source.Id].FlowEvt = []int{}
							}
							flowidmap[srcdepobj.SrcDep.Id].FlowDetails = socketmap[netdata.Source.Id]
							socketmap[netdata.Source.Id].FlowEvt = append(socketmap[netdata.Source.Id].FlowEvt, netdata.Source.Id)
						}
						//} else {
						//	//log.Println("Source dep does not exist", netdata.Source.Id, netdata.Type, srcdepobj.SrcDep.Id)
						//}

					case "HTTP_STREAM_JOB_CONTROLLER", "PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST":
						if _, fexist := flowidmap[netdata.Source.Id]; netdata.Source.Id > 0 && fexist {
							nevt := SEvent{Ts: curTs, Type: netdata.Type}
							flowidmap[netdata.Source.Id].Timing.HttpStreamJobCtr = append(flowidmap[netdata.Source.Id].Timing.HttpStreamJobCtr, nevt)
						}
					case "HTTP_STREAM_REQUEST_STARTED_JOB":
						if _, fexist := flowidmap[netdata.Source.Id]; netdata.Source.Id > 0 && fexist {
							nevt := SEvent{Ts: curTs, Type: netdata.Type}
							flowidmap[netdata.Source.Id].Timing.HttpStreamJobCtr = append(flowidmap[netdata.Source.Id].Timing.HttpStreamJobCtr, nevt)
							srcdep, _ := json.Marshal(netdata.Param)
							srcdepobj := ParamsSrcDep{}
							_ = json.Unmarshal(srcdep, &srcdepobj)
							if _, bexist := flowidmap[srcdepobj.SrcDep.Id]; !bexist {
								flowidmap[srcdepobj.SrcDep.Id] = flowidmap[netdata.Source.Id]
								flowidmap[netdata.Source.Id].EvtIds = append(flowidmap[netdata.Source.Id].EvtIds, srcdepobj.SrcDep.Id)
							}
						}

					case "HTTP_STREAM_JOB_WAITING", "HTTP_STREAM_JOB_BOUND_TO_REQUEST":
						if _, fexist := flowidmap[netdata.Source.Id]; netdata.Source.Id > 0 && fexist {
							nevt := SEvent{Ts: curTs, Type: netdata.Type}
							flowidmap[netdata.Source.Id].Timing.HttpStream = append(flowidmap[netdata.Source.Id].Timing.HttpStream, nevt)
						}
					case "HTTP_TRANSACTION_SEND_REQUEST_HEADERS", "HTTP_TRANSACTION_READ_RESPONSE_HEADERS":
						if _, fexist := flowidmap[netdata.Source.Id]; netdata.Source.Id > 0 && fexist {
							httpparam, _ := json.Marshal(netdata.Param)
							httpobj := ParamsHTTP{}
							_ = json.Unmarshal(httpparam, &httpobj)
							if net_evttype == "HTTP_TRANSACTION_SEND_REQUEST_HEADERS" {
								flowidmap[netdata.Source.Id].RequestHeader = append(httpobj.Headers, httpobj.Request)
								var http_request_header string
								http_request_header = httpobj.Request
								for _,h_value := range httpobj.Headers{
									http_request_header += h_value + "\r\n"
								}
								http_request_header += "\r\n"
								flowidmap[netdata.Source.Id].RequestHeaderString = http_request_header
							} else if net_evttype == "HTTP_TRANSACTION_READ_RESPONSE_HEADERS" {
								flowidmap[netdata.Source.Id].ResponseHeader = httpobj.Headers
								for _, headerline := range httpobj.Headers {
									clenarr := clenregx.FindStringSubmatch(headerline)
									//contained Content-Length
									if len(clenarr) == 2 {
										flowidmap[netdata.Source.Id].ContentLength, _ = strconv.ParseInt(clenarr[1], 10, 64)
									}
								}
							}
							evt := SEvent{Ts: curTs, Type: netdata.Type}
							flowidmap[netdata.Source.Id].Timing.UrlRequestStart = append(flowidmap[netdata.Source.Id].Timing.UrlRequestStart, evt)
						}
					case "UPLOAD_DATA_STREAM_READ":
						if _, fexist := flowidmap[netdata.Source.Id]; fexist && netdata.Phase == 1 && netdata.Source.Id > 0 {
							postupdate, _ := json.Marshal(netdata.Param)
							postupdateobj := ParamsCurPos{}
							_ = json.Unmarshal(postupdate, &postupdateobj)
							sprog := SProgress{Ts: curTs, LoadedByte: postupdateobj.CurrentPosition}
							flowidmap[netdata.Source.Id].Timing.Progress = append(flowidmap[netdata.Source.Id].Timing.Progress, sprog)
						}
					case "URL_REQUEST_JOB_FILTERED_BYTES_READ":
						//GET data progress
						if _, fexist := flowidmap[netdata.Source.Id]; netdata.Source.Id > 0 && fexist {
							if flowidmap[netdata.Source.Id].Method == "GET" {
								getupdate, _ := json.Marshal(netdata.Param)
								getupdateobj := ParamsByteCnt{}
								_ = json.Unmarshal(getupdate, &getupdateobj)
								sprog := SProgress{Ts: curTs}
								if len(flowidmap[netdata.Source.Id].Timing.Progress) == 0 {
									sprog.LoadedByte = getupdateobj.ByteCount
									flowidmap[netdata.Source.Id].Timing.Progress = append(flowidmap[netdata.Source.Id].Timing.Progress, sprog)
								} else {
									lastprog := flowidmap[netdata.Source.Id].Timing.Progress[len(flowidmap[netdata.Source.Id].Timing.Progress)-1]
									sprog.LoadedByte = getupdateobj.ByteCount + lastprog.LoadedByte
								}
								flowidmap[netdata.Source.Id].Timing.Progress = append(flowidmap[netdata.Source.Id].Timing.Progress, sprog)
							}
						}
					default:
					}
				}else{
					log.Println("could not find the log event type num in constdata")
				}


			}
		}
	}
	for fid, flow := range flowidmap {
		if fid == flow.EvtIds[0] {
			netlogrec.Flows = append(netlogrec.Flows, flow)
		}
	}
	return netlogrec
}
