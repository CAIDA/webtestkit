package ndt

import (
	"log"
	"strconv"
	"cloudanalysis/analysis"
	"cloudanalysis/common"
	"cloudanalysis/savedata"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

//plot TCP download flows
func NdtPlotFlow(filename string, ct NdtTest) {
	metatiming := ct.Meta
	measflow := ct.Flowmap
	ptotal, err := plot.New()

	ival := 0.05
	pcaptput := analysis.OverallTput{Interval: ival, FlowsTput: []plotter.XYs{}}
	downcsv := &savedata.SaveCSV{}
	_ = downcsv.NewCSV(common.Getfilename(filename) + ".down.csv")
	for _, flow := range measflow {
		if flow.DownUp == 0 {
			log.Println("Flow th", flow.SrcPort)
			ap := analysis.PcapTput(metatiming.IndexPcap, flow.Port, flow.PcapInfo, ival)
			for _, pdata := range ap {
				tmpdata := []string{strconv.FormatFloat(pdata.X, 'f', -1, 64), flow.Host, flow.Port, flow.SrcPort, "1", strconv.FormatFloat(pdata.Y, 'f', -1, 64)}
				downcsv.AddOneToCSV(tmpdata)
			}
			pcaptput.AddTput(ap)
			/*			if len(accp) > 0 && len(accr) > 0 {
						factor := float64(len(accr)) / float64(len(accp))
					}*/

		}
	}
	_ = downcsv.CloseCSV()
	err = plotutil.AddLinePoints(ptotal, "Pcap", pcaptput.TotalTput())
	if err != nil {
		log.Fatal(err)
	}
	//ptotal.W
	ptotal.Title.Text = "Total throughput"
	ptotal.Y.Label.Text = "Throughput /Mbps"
	totalthname := common.Getfilename(filename) + ".allthput.eps"
	if err := ptotal.Save(10*vg.Inch, 4*vg.Inch, totalthname); err != nil {
		log.Fatal(err)
	}
}

func NdtPlotUpload(filename string, ct NdtTest) {
	metatiming := ct.Meta
	measflow := ct.Flowmap
	p, err := plot.New()

	ival := 0.05
	pcaptputwopt := analysis.OverallTput{Interval: ival, FlowsTput: []plotter.XYs{}}

	upcsv := &savedata.SaveCSV{}
	_ = upcsv.NewCSV(common.Getfilename(filename) + ".upload.csv")
	for _, flow := range measflow {
		if flow.DownUp == 1 {
			ap := analysis.PcapUpTput(metatiming.IndexPcap, flow.Port, flow.PcapInfo, ival)
			//		log.Println("upload flow", flow.Port, len(flow.PcapInfo.PckDump), ap, ax)
			//accp := AccumPcap(metatiming.IndexPcap, flow.Port, flow.PcapInfo.PckDump)
			pcaptputwopt.AddTput(ap)
			for _, pdata := range ap {
				tmpdata := []string{strconv.FormatFloat(pdata.X, 'f', -1, 64), flow.Host, flow.Port, flow.SrcPort, "1", strconv.FormatFloat(pdata.Y, 'f', -1, 64)}
				upcsv.AddOneToCSV(tmpdata)
			}
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
	err = plotutil.AddLinePoints(p, "pcap", pcaptputwopt.TotalTput())
	log.Println(pcaptputwopt.TotalTput())
	_ = upcsv.CloseCSV()
	if err != nil {
		log.Fatal(err)
	}
	//ptotal.W
	p.Title.Text = "Upload Througput"
	p.Y.Label.Text = "Throughput /Mbps"
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
}
