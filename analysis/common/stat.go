package common

import (
	"gonum.org/v1/gonum/stat"
	"gonum.org/v1/plot/plotter"
)

func ECDF(samples []float64) plotter.XYs {
	n := len(samples)
	stat.SortWeighted(samples, nil)
	ecdfs := make(plotter.XYs, n)
	for i := 0; i < n; i++ {
		ecdfs[i].X = samples[i]
		ecdfs[i].Y = stat.CDF(samples[i], stat.Empirical, samples, nil)
	}
	return ecdfs
}
