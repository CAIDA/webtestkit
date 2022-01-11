package common

import (
	"analysis/netlog"
	"analysis/tracelog"
	"analysis/tsharkutil"
)

//basic data structure for all speed test measurement flows
type MeasFlow struct {
	Url         string
	Host        string
	DstIp       string
	Port        string //dst port
	SrcIp       string
	SrcPort     string
	ReqId       string
	EvtId       int
	RangeLen    int
	Random      string
	OptionReqId string
	DownUp      int
	Rrs         tracelog.FlowDetail
	XhrTiming   tracelog.XhrFlow
	PcapInfo    tsharkutil.StreamPcap
	NetLogInfo  *netlog.FlowNetLog
}

type MetaTiming struct {
	Index         int64
	IndexPcap     float64
	IndexNetlog   int64
	DownloadStart int64
	DownloadEnd   int64
	UploadStart   int64
	UploadEnd     int64
}

type TestSummary struct {
	SourceFiles     *FilePaths
	Meta            *MetaTiming
	Flows           []*MeasFlow
	Flowmap         map[string]*MeasFlow
	CounterTimeline []*tracelog.Counters
	PckNum          int
	RttList         map[int]*tsharkutil.RTT_Stream
}
