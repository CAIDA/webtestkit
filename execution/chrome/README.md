# WebTestKit Execution modules (Chrome)

This directory contains node.js scripts that used puppeteer (https://pptr.dev) to automatically execute different speed tests.
## Installation
``bash
#install node.js
curl -fsSL https://deb.nodesource.com/setup_current.x | sudo -E bash -
sudo apt-get install -y nodejs
#install puppeteer
npm i puppeteer
``
## Execution
### Ookla speedtest.net
``bash
node ookla.js --city <City> --net <Network>
``
### Comcast Xfinity speed test
``bash
node comcast.js --host <Host> --ip <4/6>
``
### Fast.com
``bash
node fast.js
``
### M-Lab NDT
``bash
node ndt.js
``
### Speedof.me
``bash
node speedofme.js
``
### Cloudflare speed test
``bash
node cloudflare.js
```
