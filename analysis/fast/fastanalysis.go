package fast

import (
	"analysis/evaluation"
	"analysis/common"
	"analysis/savedata"
	"log"
	"os"
	"strconv"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
	"gonum.org/v1/plot/vg/draw"
	"gonum.org/v1/plot/vg/vgeps"
)

//Request response time
func FastPlotRRTime(filename string, metatiming *FastMetaTiming, measflow map[string]*FastMeasFlow) {
	n := len(measflow)
	XhrResDiff := make(plotter.Values, n)
	XhrPcapDiff := make(plotter.Values, n)
	ResPcapDiff := make(plotter.Values, n)
	for _, flow := range measflow {
		if flow.DownUp == 0 {
			if flow.XhrTiming.Header > 0 && flow.XhrTiming.Opened > 0 && flow.Rrs.RespTs > 0 && flow.Rrs.ReqTs > 0 {
				XhrResDiff = append(XhrResDiff, float64(flow.XhrTiming.Header-flow.XhrTiming.Opened)/1000000-float64(flow.Rrs.RespTs-flow.Rrs.ReqTs)/1000000)
			}
			if flow.Rrs.RespTs > 0 && flow.Rrs.ReqTs > 0 && flow.PcapInfo.Response != nil && flow.PcapInfo.Request != nil {
				if flow.PcapInfo.Response.Ts > 0 && flow.PcapInfo.Request.Ts > 0 {
					ResPcapDiff = append(ResPcapDiff, float64(flow.Rrs.RespTs-flow.Rrs.ReqTs)/1000000-float64(flow.PcapInfo.Response.Ts-flow.PcapInfo.Request.Ts))
				}
			}
			if flow.XhrTiming.Header > 0 && flow.XhrTiming.Opened > 0 && flow.PcapInfo.Response != nil && flow.PcapInfo.Request != nil {

				if flow.PcapInfo.Response.Ts > 0 && flow.PcapInfo.Request.Ts > 0 {
					XhrPcapDiff = append(XhrPcapDiff, float64(flow.XhrTiming.Header-flow.XhrTiming.Opened)/1000000-float64(flow.PcapInfo.Response.Ts-flow.PcapInfo.Request.Ts))
				}
			}
		}
	}
	p := plot.New()
	//if err != nil {
	//	log.Fatal(err)
	//}
	p.Title.Text = "Boxplot Request-Response Time diff"
	p.Y.Label.Text = "Overhead /s"
	w := vg.Points(20)
	b0, err := plotter.NewBoxPlot(w, 0, XhrResDiff)
	if err != nil {
		panic(err)
	}
	b1, err := plotter.NewBoxPlot(w, 1, XhrPcapDiff)
	if err != nil {
		panic(err)
	}
	b2, err := plotter.NewBoxPlot(w, 2, ResPcapDiff)
	if err != nil {
		panic(err)
	}
	p.Add(b0, b1, b2)
	p.NominalX("XhrRes", "XhrPcap", "ResPcap")
	rrtimename := common.Getfilename(filename) + ".rrbox.pdf"
	if err := p.Save(4*vg.Inch, 5*vg.Inch, rrtimename); err != nil {
		log.Fatal(err)
	}
	pcdf := plot.New()
	if err != nil {
		log.Fatal(err)
	}
	pcdf.Title.Text = "CDF of Overhead"
	err = plotutil.AddLinePoints(pcdf,
		"XHRRes", common.ECDF(XhrResDiff),
		"XHRPcap", common.ECDF(XhrPcapDiff),
		"ResPcap", common.ECDF(ResPcapDiff))
	if err != nil {
		log.Fatal(err)
	}
	//	pcdf.Legend.Top = true
	//	pcdf.Legend.Left = true
	pcdf.X.Min = 0
	pcdf.Y.Min = 0
	pcdf.Y.Max = 1
	pcdf.Y.Label.Text = "CDF"
	pcdf.X.Label.Text = "Difference in HTTP Request-Response time/s"
	rrcdfname := common.Getfilename(filename) + ".rrcdf.eps"
	if err := pcdf.Save(4*vg.Inch, 4*vg.Inch, rrcdfname); err != nil {
		log.Fatal(err)
	}

}

//plot TCP download flows
func FastPlotFlow(filename string, ct FastTest) {
	var err error
	metatiming := ct.Meta
	measflow := ct.Flowmap
	p := plot.New()
	pr := plot.New()
	pth := plot.New()
	pxth := plot.New()
	ptotal := plot.New()


	ival := 0.05
	pcaptput := evaluation.OverallTput{Interval: ival, FlowsTput: []plotter.XYs{}}
	xtput := evaluation.OverallTput{Interval: ival, FlowsTput: []plotter.XYs{}}
	downcsv := &savedata.SaveCSV{}
	_ = downcsv.NewCSV(common.Getfilename(filename) + ".down.csv")
	for _, flow := range measflow {
		if flow.Rrs.Method == "GET" {
			log.Println(flow.ReqId, flow.Port, len(flow.Rrs.RrsTimeline))
			ap := evaluation.PcapTput(metatiming.IndexPcap, flow.Port, flow.PcapInfo, ival)
			ax := evaluation.XhrTput(flow.Rrs, flow.XhrTiming, ival)
			for _, pdata := range ap {
				tmpdata := []string{strconv.FormatFloat(pdata.X, 'f', -1, 64), flow.Host, flow.Port, flow.SrcPort, "1", strconv.FormatFloat(pdata.Y, 'f', -1, 64)}
				downcsv.AddOneToCSV(tmpdata)
			}
			for _, xdata := range ax {
				tmpdata := []string{strconv.FormatFloat(xdata.X, 'f', -1, 64), flow.Host, flow.Port, flow.SrcPort, "2", strconv.FormatFloat(xdata.Y, 'f', -1, 64)}
				downcsv.AddOneToCSV(tmpdata)
			}

			accp := evaluation.AccumPcap(metatiming.IndexPcap, flow.Port, flow.PcapInfo.PckDump)
			accr := evaluation.AccumRrs(metatiming.Index, flow.Rrs)
			pcaptput.AddTput(ap)
			xtput.AddTput(ax)
			err = plotutil.AddLinePoints(p, accp)
			err = plotutil.AddLinePoints(pr, accr)
			err = plotutil.AddLinePoints(pth, evaluation.PcapTput(metatiming.IndexPcap, flow.Port, flow.PcapInfo, ival))
			err = plotutil.AddLinePoints(pxth, evaluation.XhrTput(flow.Rrs, flow.XhrTiming, ival))
			if len(accp) > 0 && len(accr) > 0 {
				factor := float64(len(accr)) / float64(len(accp))
				log.Println("Pcap:", len(accp), "rrs:", len(accr), factor)
			}
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	err = plotutil.AddLinePoints(ptotal, "Pcap", pcaptput.TotalTput(), "XHR", xtput.TotalTput())
	_ = downcsv.CloseCSV()
	if err != nil {
		log.Fatal(err)
	}

	p.Title.Text = "pcap Flow progress"
	pr.Title.Text = "Rrs Flow progress"
	p.Y.Label.Text = "Downloaded data /bytes"
	pr.Y.Label.Text = "Downloaded data /bytes"
	pth.Title.Text = "pcap throughput"
	pth.Y.Label.Text = "Throughput /Mbps"
	pxth.Title.Text = "XHR throughput"
	pxth.Y.Label.Text = "Throughput /Mbps"
	ptotal.Title.Text = "Total throughput"
	ptotal.Y.Label.Text = "Throughput /Mbps"
	p.X.Min = 0
	p.X.Max = 15
	pr.X.Min = 0
	pr.X.Max = 15
	pth.X.Min = 0
	pth.X.Max = 15
	pxth.X.Min = 0
	pxth.X.Max = 15
	ptotal.X.Min = 0
	ptotal.X.Max = 15
	/*	thname := common.Getfilename(filename) + ".pflow.pdf"
		rthname := common.Getfilename(filename) + ".rflow.pdf"
		pthname := common.Getfilename(filename) + ".pth.pdf"
		xthname := common.Getfilename(filename) + ".xth.pdf"
		totalthname := common.Getfilename(filename) + ".thtotal.pdf"
	*/
	plots := make([][]*plot.Plot, 3)
	plots[0] = make([]*plot.Plot, 1)
	plots[1] = make([]*plot.Plot, 1)
	plots[2] = make([]*plot.Plot, 1)
	//	plots[3] = make([]*plot.Plot, 1)
	//	plots[4] = make([]*plot.Plot, 1)
	//	plots[0][0] = p
	//	plots[1][0] = pr
	plots[0][0] = pth
	plots[1][0] = pxth
	plots[2][0] = ptotal

	img := vgeps.New(vg.Points(500), vg.Points(800))
	dc := draw.New(img)
	t := draw.Tiles{
		Rows:      3,
		Cols:      1,
		PadX:      vg.Millimeter,
		PadY:      vg.Millimeter,
		PadTop:    vg.Points(2),
		PadBottom: vg.Points(2),
		PadLeft:   vg.Points(2),
		PadRight:  vg.Points(2),
	}
	canvases := plot.Align(plots, t, dc)
	for c := 0; c < 3; c++ {
		plots[c][0].Draw(canvases[c][0])
	}
	w, err := os.Create(common.Getfilename(filename) + ".allthput.eps")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := img.WriteTo(w); err != nil {
		log.Fatal(err)
	}

}

func FastPlotUpload(filename string, ct FastTest) {
	var err error
	metatiming := ct.Meta
	measflow := ct.Flowmap
	p := plot.New()

	pth := plot.New()
	//if err != nil {
	//	log.Fatal(err)
	//}
	ival := 0.05
	pcaptputwopt := evaluation.OverallTput{Interval: ival, FlowsTput: []plotter.XYs{}}
	xhrtput := evaluation.OverallTput{Interval: ival, FlowsTput: []plotter.XYs{}}
	rrstput := evaluation.OverallTput{Interval: ival, FlowsTput: []plotter.XYs{}}

	downcsv := &savedata.SaveCSV{}
	_ = downcsv.NewCSV(common.Getfilename(filename) + ".up.csv")
	for _, flow := range measflow {
		if flow.DownUp == 1 {
			ap := evaluation.PcapUpTput(metatiming.IndexPcap, flow.Port, flow.PcapInfo, ival)
			ax := evaluation.XhrUpTput(metatiming.IndexPcap, metatiming.Index, flow.Port, flow.PcapInfo, flow.XhrTiming, ival)
			ar := evaluation.RrsUpTput(metatiming.IndexPcap, metatiming.Index, flow.Port, flow.PcapInfo, flow.Rrs.Timing, flow.Rrs.ReqTs, flow.Rrs.RespTs, ival)
			for _, pdata := range ap {
				tmpdata := []string{strconv.FormatFloat(pdata.X, 'f', -1, 64), flow.Host, flow.Port, flow.SrcPort, "1", strconv.FormatFloat(pdata.Y, 'f', -1, 64)}
				downcsv.AddOneToCSV(tmpdata)
			}
			for _, xdata := range ax {
				tmpdata := []string{strconv.FormatFloat(xdata.X, 'f', -1, 64), flow.Host, flow.Port, flow.SrcPort, "2", strconv.FormatFloat(xdata.Y, 'f', -1, 64)}
				downcsv.AddOneToCSV(tmpdata)
			}

			log.Println("upload flow", flow.ReqId, flow.XhrTiming, ap, ax, ar)
			//accp := AccumPcap(metatiming.IndexPcap, flow.Port, flow.PcapInfo.PckDump)
			pcaptputwopt.AddTput(ap)
			xhrtput.AddTput(ax)
			rrstput.AddTput(ar)
			err = plotutil.AddLinePoints(pth, evaluation.PcapUpTput(metatiming.IndexPcap, flow.Port, flow.PcapInfo, ival))
			/*			err = plotutil.AddLinePoints(p, accp)
						err = plotutil.AddLinePoints(pr, accr)
						err = plotutil.AddLinePoints(pth, PcapTput(metatiming.IndexPcap, flow.Port, flow.PcapInfo, 0.5))
						err = plotutil.AddLinePoints(pxth, XhrTput(flow.Rrs, 0.5))
						if len(accp) > 0 && len(accr) > 0 {
							factor := float64(len(accr)) / float64(len(accp))
							log.Println("Pcap:", len(accp), "rrs:", len(accr), factor)
						}
						if err != nil {
							log.Fatal(err)
						}*/
		}
	}
	err = plotutil.AddLinePoints(p, "XHR", xhrtput.TotalTput(), "RRS", rrstput.TotalTput(), "pcap", pcaptputwopt.TotalTput())
	_ = downcsv.CloseCSV()
	log.Println(xhrtput.TotalTput())
	log.Println(rrstput.TotalTput())
	log.Println(pcaptputwopt.TotalTput())
	if err != nil {
		log.Fatal(err)
	}
	//ptotal.W
	p.Title.Text = "Upload Througput"
	p.Y.Label.Text = "Throughput /Mbps"
	p.X.Min = 0
	p.X.Max = 25
	pth.X.Min = 0
	pth.X.Max = 25
	/*	thname := common.Getfilename(filename) + ".pflow.pdf"
		rthname := common.Getfilename(filename) + ".rflow.pdf"
		pthname := common.Getfilename(filename) + ".pth.pdf"
		xthname := common.Getfilename(filename) + ".xth.pdf"
		totalthname := common.Getfilename(filename) + ".thtotal.pdf"
	*/
	uploadname := common.Getfilename(filename) + ".upload.eps"
	if err := p.Save(4*vg.Inch, 2*vg.Inch, uploadname); err != nil {
		log.Fatal(err)
	}
	uploadflowname := common.Getfilename(filename) + ".uploadflow.eps"
	if err := pth.Save(4*vg.Inch, 2*vg.Inch, uploadflowname); err != nil {
		log.Fatal(err)
	}

}


