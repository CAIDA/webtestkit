# webspeedtestanalysis

This is the code for analyzing traffic of web-based speedtest platforms. To run this code, please use the following command:

```
go run webspanalysis.go
```
In webspanalysis.go, "datapath" should be changed to the local path where webspeedtest data are stored.
The file structure should be in the form of: $datapath/$node/$platform, where $node is the vm name for running the experiments and $platform is the webspeedtest application name (e.g., ookla, speedtest).

Additionally there are some variables which could be changed. When "toverify" is set to True, this program will automatically verify how accurate the algorithm is (only meaningful when the packets are fully captured.)
When "cleanrun" is enabled, all former running results in the same directory are deleted. 