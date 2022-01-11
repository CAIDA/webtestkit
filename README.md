# WebTestKit

This repository contains the code for WebTestKit: a unified and configurable framework for facilitating automatic test execution and cross-layer analysis of web-based speed tests. 

## Abstract 

Web-based speed test platforms are popular among end-users for measuring their available bandwidth. Thousands of measurement servers have been deployed in diverse geographical and network locations to serve users worldwide. However, these platforms work on top of encrypted measurement traffic and only report simple aggregated test results. Thus, it is difficult for the research community to understand these results especially with their opaque methodology and run-time dynamics, let alone leveraging these platforms for different studies. In this paper, we propose WebTestKit, a unified and configurable framework for facilitating automatic test execution and cross-layer analysis of test results for five major web-based speed test platforms. Only capturing packet headers of traffic traces, WebTestKit is capable of performing in-depth analysis by precisely extracting HTTP and timing information from test runs. Our testbed experiments showed WebTestKit is lightweight and accurate in interpreting encrypted measurement traffic. We applied WebTestKit to compare the use of HTTP requests across speed tests and investigate the root causes for impeding the accuracy of latency measurements, which play an important role in test server selection and throughput estimation.

## Installation Guide

1. __Clone this repository__

2. __Install node.js & puppeteer__
	```bash
	#install node.js
	curl -fsSL https://deb.nodesource.com/setup_current.x | sudo -E bash -
	sudo apt-get install -y nodejs
	#install puppeteer
	npm i puppeteer
	```

3. __Install Golang__

    Follow the steps described here:
    ```bash
    https://go.dev/doc/install
    ```
4. __Install gonum__

    Follow the steps decribed here:
    ```bash
    https://go.dev/doc/install
    ```
    First, using go get:
        ```
        go get -u gonum.org/v1/gonum/...
        ```      
## System components

* __servercrawling module__

    discovering available measurement servers in speed test infrastructures.

* __execution module__

    automating the execution of speed tests and capture data from different layers using [someta](https://github.com/jsommers/someta), [tcpdump](https://www.tcpdump.org) and [netlog](https://www.chromium.org/developers/design-documents/network-stack/netlog).

* __analysis module__

    performing analysis of data collected in the execution module





