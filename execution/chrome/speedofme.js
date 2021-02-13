'use strict';

const puppeteer = require('puppeteer');
const fs = require('fs');
var tracename = "speedofme";
//console.log(process.argv.length)
if (process.argv.length >= 3) {
    tracename = process.argv[2];
}
var globaltimeout = 120000;
(
    async () => {
        var tracejson = "./" + tracename + ".json";
        var errorfile = "./" + tracename + ".err";
        var printscnname = "./" + tracename + ".png";
        var printerrname = "./" + tracename + ".err.png";
        var keyarg = "--ssl-key-log-file=./"+tracename+".key";
        var netlogarg = "--log-net-log=./"+tracename+".netlog";
        console.log("speedofme:" + tracejson);
        const browser = await puppeteer.launch({ headless: true ,args: [keyarg, netlogarg]})
        const page = await browser.newPage()
        // await page.setViewport({width: 1240, height:1024})

        console.log(tracejson);

        //await page.tracing.start({path: 'trace.json', categories: ['devtools.timeline']})
        await page.tracing.start({ path: tracejson, categories: ['devtools.timeline', 'blink.user_timing'] })
        //await page.tracing.start({path: tracejson})
        await page.goto('https://speedof.me')
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error goto");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        await page.click('#cc-accept-btn')
            .catch((err) => {
            });

        await page.click('#start_test_btn')
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error start");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        //        await page.waitForFunction('document.getElementsByClassName("share-btn-group")[0].style.cssText == "display: inline;"', { timeout: globaltimeout })
        await page.waitForFunction('document.getElementsByClassName("pass-circle-group")[0].style.display == "none"', { timeout: globaltimeout })
            .catch((err) => {
                fs.writeFileSync(errorfile, "Jump to result");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });


        await page.screenshot({ path: printscnname });

        const summaryoks = await page.$$eval('#d3_pane > svg > g.meter-group > text', el => el.map(e => e.textContent))
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error summary");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });
        // 121.8  download speed
        // 225.2   upload speed
        // 7       latency
        // 124.244.108.236  your ip
        // Hong Kong 3   test server
        // 201.17   max dowanload
        // 225.2     max  upload
        // DOWNLOAD SPEED (Mbps)
        // UPLOAD SPEED (Mbps)
        // LATENCY (ms)
        // YOUR IP ADDRESS
        // TEST SERVER
        // Max.
        // Max.

        // for(let i = 0, len = summaryoks.length; i < len; i++){
        //      await console.log(summaryoks[i])
        //     }
        try {
            let speedvalue = summaryoks[0];
            let ulspeedvalue = summaryoks[1];
            let latencyvalue = summaryoks[2];
            let maxdownloadvalue = summaryoks[5];
            let maxupvalue = summaryoks[6];
            let servervalue = summaryoks[4];
            let resultstring = speedvalue + ";" + ulspeedvalue + ";" + latencyvalue + ";" + maxdownloadvalue + ";" + maxupvalue + ";" + servervalue;
            console.log(resultstring);
            fs.writeFileSync(tracename + ".web.csv", resultstring);
        } catch (err) {
            fs.writeFileSync(errorfile, "Error parsing result");
            fs.writeFileSync(errorfile, summaryok);
        }
        await page.tracing.stop()
        await browser.close();
    }
)()