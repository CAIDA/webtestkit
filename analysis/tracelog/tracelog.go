package tracelog

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"math"
)

type PerfLog struct {
	Pid  int    `json:"pid"`
	Tid  int    `json:"tid"`
	Ts   int64  `json:"ts"`
	Ph   string `json:"ph"`
	Cat  string `json:"cat"`
	Name string `json:"name"`
	Args json.RawMessage
	Dur  int   `json:"dur"`
	Tdur int   `json:"tdur"`
	Tts  int64 `json:"tts"`
}

type XhrReady struct {
	Data struct {
		URL        string `json:"url"`
		ReadyState int    `json:"readyState"`
		Frame      string `json:"frame"`
	} `json:"data"`
}

type RrsRequest struct {
	Data struct {
		RequestID     string `json:"requestId"`
		Frame         string `json:"frame"`
		URL           string `json:"url"`
		RequestMethod string `json:"requestMethod"`
		Priority      string `json:"priority"`
	} `json:"data"`
}

type RespTiming struct {
	RequestTime       float64 `json:"requestTime"`
	ProxyStart        float64 `json:"proxyStart"`
	ProxyEnd          float64 `json:"proxyEnd"`
	DNSStart          float64 `json:"dnsStart"`
	DNSEnd            float64 `json:"dnsEnd"`
	ConnectStart      float64 `json:"connectStart"`
	ConnectEnd        float64 `json:"connectEnd"`
	SslStart          float64 `json:"sslStart"`
	SslEnd            float64 `json:"sslEnd"`
	WorkerStart       float64 `json:"workerStart"`
	WorkerReady       float64 `json:"workerReady"`
	SendStart         float64 `json:"sendStart"`
	SendEnd           float64 `json:"sendEnd"`
	ReceiveHeadersEnd float64 `json:"receiveHeadersEnd"`
	PushStart         float64 `json:"pushStart"`
	PushEnd           float64 `json:"pushEnd"`
}

type RrsRecvResp struct {
	Data struct {
		RequestID         string     `json:"requestId"`
		Frame             string     `json:"frame"`
		StatusCode        int        `json:"statusCode"`
		MimeType          string     `json:"mimeType"`
		EncodedDataLength float64    `json:"encodedDataLength"`
		FromCache         bool       `json:"fromCache"`
		FromServiceWorker bool       `json:"fromServiceWorker"`
		Timing            RespTiming `json:"timing"`
	} `json:"data"`
}

type RrsRcvData struct {
	Data struct {
		RequestID         string  `json:"requestId"`
		Frame             string  `json:"frame"`
		EncodedDataLength float64 `json:"encodedDataLength"`
	} `json:"data"`
}

type RrsFinish struct {
	Data struct {
		RequestID         string  `json:"requestId"`
		DidFail           bool    `json:"didFail"`
		EncodedDataLength float64 `json:"encodedDataLength"`
		DecodedBodyLength float64 `json:"decodedBodyLength"`
		FinishTime        float64 `json:"finishTime"`
	} `json:"data"`
}

type CounterData struct {
	Data struct {
		Documents   int     `json:"documents"`
		Node        int     `json:"nodes"`
		JsListeners int     `json:"jsEventListeners"`
		JsHeap      float64 `json:"jsHeapSizeUsed"`
	} `json:"data"`
}

type AllLog struct {
	TraceEvents []PerfLog `json:"traceEvents"`
}

type Timeline struct {
	Ts     int64
	Length float64
}

type FlowDetail struct {
	ReqTs       int64
	RespTs      int64
	Method      string
	StatusCode  int
	Priority    string
	BindedReq   string
	Timing      RespTiming
	RrsTimeline []Timeline
}

type XhrFlow struct {
	Unsent  int64
	Opened  int64
	Header  int64
	Done    int64
	Loading []int64
}

type Counters struct {
	Ts       int64
	Listener int
	HeapSize float64
}

type XhrThroughput struct {
	STs       float64
	ETs       float64
	Slot      float64
	ByteTotal float64
	Tput      float64
}

func ReadLog(logfile string, msgch chan PerfLog) {
	logbyte, err := ioutil.ReadFile(logfile)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Read File")
	var logs AllLog
	if err = json.Unmarshal(logbyte, &logs); err != nil {

		log.Fatal("file name: ", logfile, err)

	}
	log.Println("Unmarshaled")
	for _, evt := range logs.TraceEvents {
		switch evt.Name {
		case "ResourceSendRequest", "ResourceReceiveResponse", "ResourceReceivedData", "XHRReadyStateChange", "navigationStart", "UpdateCounters":
			msgch <- evt

			/*var rdata RrsRcvData
			if err := json.Unmarshal(evt.Args, &rdata); err == nil {
				log.Println("ts:", evt.Ts, " ", rdata.Data.RequestID, " ", rdata.Data.EncodedDataLength)
			} else {
				log.Println(err)
			}
			var xarg XhrReady
			if err := json.Unmarshal(evt.Args, &xarg); err == nil {
				log.Println("ts:", evt.Ts, " ", xarg.Data.URL)
			} else {
				log.Println(err)
			}
			*/
		}
	}
	close(msgch)
}

func XhrThput(flow FlowDetail, xflow XhrFlow, interval float64) []*XhrThroughput {
	if len(flow.RrsTimeline) > 0 {
		th := []*XhrThroughput{}
		var curinterval float64
		startts := float64(flow.RrsTimeline[0].Ts) / 1000000
		//		curinterval = math.Floor(float64(xflow.Opened) / 1000000 / interval)
		curinterval = math.Floor(startts / interval)
		curdown := &XhrThroughput{STs: startts, Slot: curinterval * interval}
		th = append(th, curdown)
		for i := 0; i < len(flow.RrsTimeline); i++ {
			rrs := flow.RrsTimeline[i]
			rrsts := float64(rrs.Ts) / 1000000
			if rrsts < (curinterval+1)*interval {
				curdown.ByteTotal += rrs.Length
				curdown.ETs = rrsts
			} else {
				curdown.Tput = float64(curdown.ByteTotal) * 8 / (interval)
				curinterval = math.Floor(rrsts / interval)
				curdown = &XhrThroughput{STs: rrsts, Slot: curinterval * interval, ETs: rrsts, ByteTotal: rrs.Length, Tput: 0}
				th = append(th, curdown)
			}
		}
		if curdown.ByteTotal > 0 {
			log.Println("Fixing tail")
			//			curdown.ETs = float64(xflow.Done) / 1000000
			//	curdown.Tput = float64(curdown.ByteTotal) * 8 / (float64(xflow.Done)/1000000 - curdown.STs)
			curdown.Tput = float64(curdown.ByteTotal) * 8 / (interval)
		}
		return th

	}
	return nil

}
