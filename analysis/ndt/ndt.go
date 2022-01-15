package ndt

import (
	"log"
	"sync"
	"analysis/common"
	"analysis/savedata"
	"analysis/tracelog"
	"analysis/tsharkutil"
)



type NdtMeasFlow struct {
	//	Url     string
	Host    string
	Port    string
	SrcPort string
	DstIp   string
	//	DstPort string
	//	ReqId       string
	//	Random      string
	//	OptionReqId string
	DownUp int
	//	Rrs         tracelog.FlowDetail
	//	XhrTiming   tracelog.XhrFlow
	PcapInfo tsharkutil.StreamPcap
}

//create a tmp place before we can see resource request
/*type XhrMeta struct {
	ReqId  string
	Unsent int64
	Opened int64
}*/

type NdtMetaTiming struct {
	Index         int64
	IndexPcap     float64
	DownloadStart int64
	DownloadEnd   int64
	UploadStart   int64
	UploadEnd     int64
}

type NdtTest struct {
	Meta    *NdtMetaTiming
	Flowmap map[string]*NdtMeasFlow
	//	CounterTimeline []*tracelog.Counters
	//	pck_num         int
}

func LoadNdt(globwg *sync.WaitGroup, wchan chan int, filepath string) NdtTest {
	//	filepath := `/home/cskpmok/webspeedtestdata/US1/comcast/comcast_1539367807.json`
	log.Println("working on ", filepath)
	msgch := make(chan tracelog.PerfLog)
	go tracelog.ReadLog(filepath, msgch)
	metatiming := NdtMetaTiming{}
	measflowmap := make(map[string]*NdtMeasFlow)
	//	randreqidmap := make(map[string][]*NdtMeasFlow)
	//	cnttimeline := []*tracelog.Counters{}
	//get the timestamp of sending the DNS request
	its, srcip := tsharkutil.DNSQueryTime(filepath, "measurement-lab.org")
	/*	if its == 0 {
		log.Println("Use HTTPS:", filepath)
		its = tsharkutil.HTTPSSyncTime(filepath)
	}*/
	metatiming.IndexPcap = its
	//	log.Println("timestamp", its, srcip)
	ulflow, dlflow := tsharkutil.FindHeaviestDLULFlows(filepath, srcip)
	//	log.Println("ULDL:", ulflow, dlflow)
	alluploadpck := tsharkutil.GetSSLPckfromTuples(filepath, ulflow.SrcIp, ulflow.DstIp, ulflow.SrcPort, ulflow.DstPort)
	measflowmap["download"] = &NdtMeasFlow{DownUp: 0, Host: dlflow.DstIp, Port: dlflow.DstPort, SrcPort: dlflow.SrcPort, DstIp: dlflow.DstIp}
	measflowmap["upload"] = &NdtMeasFlow{DownUp: 1, Host: ulflow.DstIp, Port: ulflow.DstPort, SrcPort: ulflow.SrcPort, DstIp: ulflow.DstIp}
	for i := 0; i < len(alluploadpck); i++ {
		p := alluploadpck[i]
		if p.SrcIp == srcip && p.SSLRecordType == 23 {
			if p.TcpLen > 1000 && measflowmap["upload"].PcapInfo.Request == nil {
				measflowmap["upload"].PcapInfo.Request = &tsharkutil.HRequest{FrameNum: p.FrameNo, Ts: p.Ts, Method: "", Uri: ""}
			}
		} else if p.DstIp == srcip {
			if measflowmap["upload"].PcapInfo.Response == nil {
				measflowmap["upload"].PcapInfo.Response = &tsharkutil.HResponse{FrameNum: p.FrameNo, Ts: p.Ts, Code: 0, FrameEnd: p.FrameNo}
			} else {
				measflowmap["upload"].PcapInfo.Response.FrameNum = p.FrameNo
				measflowmap["upload"].PcapInfo.Response.Ts = p.Ts
				measflowmap["upload"].PcapInfo.Response.FrameEnd = p.FrameNo
			}
		}
		if measflowmap["upload"].PcapInfo.Request != nil {
			measflowmap["upload"].PcapInfo.PckDump = append(measflowmap["upload"].PcapInfo.PckDump, p.GetPckInfo())
		}
	}
	alldownloadpck := tsharkutil.GetSSLPckfromTuples(filepath, dlflow.SrcIp, dlflow.DstIp, dlflow.SrcPort, dlflow.DstPort)
	for i := 0; i < len(alldownloadpck); i++ {
		p := alldownloadpck[i]
		if p.SrcIp == srcip && p.SSLRecordType == 23 {
			if p.TcpLen > 200 && measflowmap["download"].PcapInfo.Request == nil {
				measflowmap["download"].PcapInfo.Request = &tsharkutil.HRequest{FrameNum: p.FrameNo, Ts: p.Ts, Method: "", Uri: ""}
			}
		} else if p.DstIp == srcip {
			if measflowmap["download"].PcapInfo.Response == nil {
				measflowmap["download"].PcapInfo.Response = &tsharkutil.HResponse{FrameNum: p.FrameNo, Ts: p.Ts, Code: 0, FrameEnd: p.FrameNo}
			} else {
				measflowmap["download"].PcapInfo.Response.FrameEnd = p.FrameNo
			}
		}
		if measflowmap["download"].PcapInfo.Request != nil {
			measflowmap["download"].PcapInfo.PckDump = append(measflowmap["download"].PcapInfo.PckDump, p.GetPckInfo())
		}
	}
	log.Println("Done with tshark")
	for rid, flow := range measflowmap {
		log.Println(rid, len(flow.PcapInfo.PckDump), flow.PcapInfo.Request, flow.PcapInfo.Response)

	}
	/*	var bytesize []float64
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
	alldata := NdtTest{Meta: &metatiming, Flowmap: measflowmap}
	/*err := savedata.SaveData(savedata.GobName(filepath), alldata)
	if err != nil {
		log.Fatal(err)
	}*/
	return alldata
	//	log.Println(metatiming)
}

func RunNdtAnalysis(globwg *sync.WaitGroup, wchan chan int, filepath string) {
	var alldata NdtTest
	defer globwg.Done()
	common.Makeplotdir(filepath)
	if err := savedata.LoadData(savedata.GobName(filepath), &alldata); err != nil {
		alldata = LoadNdt(globwg, wchan, filepath)
	} else {
		log.Println("Found precomputed data")
	}
	NdtPlotFlow(filepath, alldata)
	NdtPlotUpload(filepath, alldata)
	<-wchan
}

