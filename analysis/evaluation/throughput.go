package evaluation

import (
	"log"
	"math"
	"strconv"

	"analysis/tracelog"
	"analysis/tsharkutil"

	"gonum.org/v1/plot/plotter"
)

type OverallTput struct {
	Interval  float64
	FlowsTput []plotter.XYs
}

func AccumRrs(index int64, rrsflow tracelog.FlowDetail) plotter.XYs {
	var accrrsvalue float64
	accrrsvalue = 0
	tsxy := make(plotter.XYs, 0)
	tsxy = append(tsxy, plotter.XY{X: float64(rrsflow.ReqTs) / 1000000, Y: accrrsvalue})
	for _, tsline := range rrsflow.RrsTimeline {
		accrrsvalue += tsline.Length
		tsxy = append(tsxy, plotter.XY{X: float64(tsline.Ts) / 1000000, Y: accrrsvalue})
	}

	//log.Printf("AccmRrs %v\n", accrrsvalue)
	return tsxy
}

func AccumPcap(indexts float64, dstport string, pckinfo []*tsharkutil.PckInfo) plotter.XYs {
	var accpcapvalue float64
	if len(pckinfo) == 0 {
		return plotter.XYs{}
	}
	accpcapvalue = 0
	dport, _ := strconv.Atoi(dstport)
	tsxy := make(plotter.XYs, 0)
	tsxy = append(tsxy, plotter.XY{X: float64(pckinfo[0].Ts - indexts), Y: 0})
	for _, pck := range pckinfo {
		//downlink
		if pck.SrcPort == dport {
			accpcapvalue += float64(pck.TcpLen)
			tsxy = append(tsxy, plotter.XY{X: pck.Ts - indexts, Y: accpcapvalue})
		}
	}
	//log.Printf("AccmPcap %v\n", accpcapvalue)
	return tsxy
}

//return Mbps
func PcapTput(indexts float64, dstport string, stream tsharkutil.StreamPcap, interval float64) plotter.XYs {
	dport, _ := strconv.Atoi(dstport)
	downth, _ := tsharkutil.Throughput(indexts, dport, stream, interval)
	//log.Println("PTput")
	if downth != nil {
		tsxy := make(plotter.XYs, 0)
		totalbyte := 0
		for _, th := range downth {
			//		log.Println(th.Slot-indexts, th.ETs-th.STs, th.Tput, th.ByteTotal)
			tsxy = append(tsxy, plotter.XY{X: th.Slot - indexts, Y: th.Tput / 1000000})
			totalbyte += th.ByteTotal
		}
		//	log.Println("Total:", totalbyte, downth[len(downth)-1].ETs-downth[0].STs)
		return tsxy
	} else {
		return plotter.XYs{}
	}
}

func PcapUpTput(indexts float64, dstport string, stream tsharkutil.StreamPcap, interval float64) plotter.XYs {
	dport, _ := strconv.Atoi(dstport)
	upth := tsharkutil.UploadThroughput(indexts, dport, stream, interval)
	if upth != nil {
		tsxy := make(plotter.XYs, 0)
		for _, th := range upth {
			tsxy = append(tsxy, plotter.XY{X: th.Slot - indexts, Y: th.Tput / 1000000})
		}
		return tsxy
	} else {
		return plotter.XYs{}
	}

}

func XhrUpTput(pcapindexts float64, xhrindexts int64, dstport string, stream tsharkutil.StreamPcap, xhrtiming tracelog.XhrFlow, interval float64) plotter.XYs {
	dport, _ := strconv.Atoi(dstport)
	upth := tsharkutil.UploadThroughput(pcapindexts, dport, stream, interval)
	//	log.Println("Xhrup:", upth)
	if upth != nil {
		tsxy := make(plotter.XYs, 0)
		curstartinterval := math.Floor(float64(xhrtiming.Opened)/1000000/interval) * interval
		curinterval := math.Round(float64(xhrtiming.Done)/1000000/interval) * interval
		var t, avgth float64

		if xhrtiming.Done > 0 && xhrtiming.Opened > 0 {
			avgth = ((float64(upth[0].ByteTotal) * 8 / (float64(xhrtiming.Done-xhrtiming.Opened) / 1000000)) / 1000000)
		} else {
			avgth = 0
		}
		log.Println("XHRUP:", curstartinterval, xhrtiming.Opened, xhrtiming.Done, curinterval, avgth)
		if curstartinterval+interval == curinterval {
			log.Println("Fix both")
			tsxy = append(tsxy, plotter.XY{X: curstartinterval, Y: avgth * float64(xhrtiming.Done-xhrtiming.Opened) / 1000000 / interval})
			return tsxy
		} else {
			if float64(xhrtiming.Opened)/1000000 > curstartinterval {
				log.Println("Fix head")
				tsxy = append(tsxy, plotter.XY{X: curstartinterval, Y: avgth * (curstartinterval + interval - (float64(xhrtiming.Opened) / 1000000)) / interval})
			}
		}
		for t = curstartinterval + interval; t < curinterval-2*interval; t += interval {
			tsxy = append(tsxy, plotter.XY{X: t, Y: avgth})
		}
		if float64(xhrtiming.Done)/1000000 < curinterval {
			log.Println("Fix tail")
			tsxy = append(tsxy, plotter.XY{X: curinterval - interval, Y: avgth * (curinterval - float64(xhrtiming.Done)/1000000) / interval})
		}
		log.Println("bytetotal", upth[0].ByteTotal, xhrtiming.Done, xhrtiming.Opened)
		return tsxy
	} else {
		return plotter.XYs{}
	}

}
func RrsUpTput(pcapindexts float64, xhrindexts int64, dstport string, stream tsharkutil.StreamPcap, rrstiming tracelog.RespTiming, reqts, respts int64, interval float64) plotter.XYs {
	dport, _ := strconv.Atoi(dstport)
	upth := tsharkutil.UploadThroughput(pcapindexts, dport, stream, interval)
	if upth != nil && len(upth) > 0 && rrstiming.RequestTime > 0 {
		tsxy := make(plotter.XYs, 0)
		//		curstartinterval := math.Floor(float64(reqts)/1000000/interval) * interval
		//		curinterval := math.Floor(float64(respts)/1000000/interval) * interval
		startts := rrstiming.RequestTime + rrstiming.SendStart/1000 - float64(xhrindexts)/1000000
		endts := rrstiming.RequestTime + rrstiming.ReceiveHeadersEnd/1000 - float64(xhrindexts)/1000000
		curstartinterval := math.Floor(startts/interval) * interval
		curinterval := math.Round(endts/interval) * interval
		var t, avgth float64
		//navigation timing is in millisecond
		if rrstiming.SendStart > 0 && rrstiming.SendEnd > 0 {
			//			avgth = ((float64(upth[0].ByteTotal) * 8 / (float64(rrstiming.SendEnd-rrstiming.SendStart) / 1000)) / 1000000)
			avgth = ((float64(upth[0].ByteTotal) * 8 / (float64(rrstiming.ReceiveHeadersEnd-rrstiming.SendStart) / 1000)) / 1000000)
		} else {
			avgth = 0
		}
		log.Println("RRSUP:", rrstiming.RequestTime, rrstiming.SendStart, rrstiming.SendEnd, rrstiming.ReceiveHeadersEnd, startts, endts, curstartinterval, curinterval, avgth)
		if curstartinterval == curinterval-interval {
			tsxy = append(tsxy, plotter.XY{X: curstartinterval, Y: avgth * float64(rrstiming.SendEnd-rrstiming.SendStart) / 1000 / interval})
			return tsxy
		} else {
			if startts > curstartinterval {
				tsxy = append(tsxy, plotter.XY{X: curstartinterval, Y: avgth * (curstartinterval + interval - startts) / interval})
			}
			for t = curstartinterval + interval; t < curinterval-2*interval; t += interval {
				tsxy = append(tsxy, plotter.XY{X: t, Y: avgth})
			}
			if endts < curinterval {
				tsxy = append(tsxy, plotter.XY{X: curinterval - interval, Y: avgth * (endts - curinterval + interval) / interval})
			}

		}
		return tsxy
	} else {
		return plotter.XYs{}
	}

}

func (otput *OverallTput) AddTput(fthput plotter.XYs) {
	otput.FlowsTput = append(otput.FlowsTput, fthput)
}

func (otput *OverallTput) TotalTput() plotter.XYs {
	if otput.Interval == 0 {
		otput.Interval = 1
	}
	var alltput plotter.XYs
	delta := 0.0001
	for fidx, f := range otput.FlowsTput {
		//first flow, just copy
		if fidx == 0 {
			alltput, _ = plotter.CopyXYs(f)
		} else {
			for _, fbin := range f {
				xbin := math.Floor((fbin.X + delta) / otput.Interval)
				inserted := false
				for i := 0; i < alltput.Len(); i++ {
					if xbin == math.Floor((alltput[i].X+delta)/otput.Interval) {
						alltput[i].Y += fbin.Y
						inserted = true
						break
					} else if math.Floor((alltput[i].X+delta)/otput.Interval) > xbin {
						//need to insert a new bin ahead of it
						alltput = append(alltput, plotter.XY{})
						copy(alltput[i+1:], alltput[i:])
						alltput[i] = fbin
						inserted = true
						break
						//						alltput = append(alltput[:i-1], fbin,alltput[i:])
					}

				}
				if !inserted {
					//append to the end
					alltput = append(alltput, fbin)
				}
			}
		}
	}
	return alltput
}

func XhrTput(flow tracelog.FlowDetail, xflow tracelog.XhrFlow, interval float64) plotter.XYs {
	th := tracelog.XhrThput(flow, xflow, interval)
	log.Println("XTput")
	if th != nil {
		tsxy := make(plotter.XYs, 0)
		totalbyte := 0.0
		for _, tvalue := range th {
			log.Println(tvalue.Slot, tvalue.ETs-tvalue.STs, tvalue.Tput, tvalue.ByteTotal)
			if tvalue.Tput == math.Inf(+1) {
				continue
			}
			tsxy = append(tsxy, plotter.XY{X: tvalue.Slot, Y: tvalue.Tput / 1000000})
			totalbyte += tvalue.ByteTotal
		}
		log.Println("Total:", totalbyte, th[len(th)-1].ETs-th[0].STs)
		return tsxy
	} else {
		return plotter.XYs{}
	}
}
