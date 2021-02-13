'use strict';

const puppeteer = require('puppeteer');
const fs = require('fs');
var tracename = "ndt";
//console.log(process.argv.length)
if (process.argv.length>=3){
    tracename = process.argv[2];
}
var globaltimeout = 120000;
(
    async ()=>{
        var tracejson = "./"+tracename+".json";
        var errorfile = "./"+tracename+".err";
        var printscnname = "./"+tracename+".png";
        var printerrname = "./"+tracename+".err.png";
        var keyarg = "--ssl-key-log-file=./"+tracename+".key";
        var netlogarg = "--log-net-log=./"+tracename+".netlog";
        console.log("ndt:"+tracejson);
        const browser = await puppeteer.launch({ headless: true , args: [keyarg, netlogarg] })
        const page = await browser.newPage()
        await page.setViewport({width: 1240, height:1024})
        //await page.tracing.start({path: 'trace.json', categories: ['devtools.timeline']})
        //await page.tracing.start({path: tracejson})
        await page.tracing.start({path: tracejson, categories: ['devtools.timeline','blink.user_timing']})
        await page.goto('https://www.measurementlab.net/p/ndt-ws.html')
          .catch((err)=>{
                fs.writeFileSync(errorfile,"Error goto");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            });
        //await page.screenshot({path: printerrname})
        //        await page.mouse.click(64,540)
        await page.waitFor(2000)
        //await page.click('a[href="#test"]')
        await page.click('.start')
          .catch((err)=>{
                fs.writeFileSync(errorfile,"Error start");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            });
        const speedmsg = await page.mainFrame()
            .waitForSelector('#results',{visible:true, timeout: globaltimeout})
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error result");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
            /*    .then(async ()=>{
                const speedvalue = await page.$eval('#speed-value', el => el.innerText);
                console.log("speed done"+speedvalue);
            })*/
        await page.screenshot({path: printscnname})
        
        const speedvalue= await page.$eval('#download-speed', el=>el.innerText)
           .catch((err)=>{
            fs.writeFileSync(errorfile,"Error speedvalue");
            fs.writeFileSync(errorfile,err);
            page.screenshot({path: printerrname})
        });
        const ulspeedvalue= await page.$eval('#upload-speed', el=>el.innerText)
           .catch((err)=>{
            fs.writeFileSync(errorfile,"Error ulspeedvalue");
            fs.writeFileSync(errorfile,err);
            page.screenshot({path: printerrname})
           });

        //        var serverloc = await page.$eval('.address')

        //console.log(serverloc)
            /*        const proto = await page.$eval(', el=>el.innerText)
        var speedvalue,ulspeedvalue,latency;
        let ip=4
        if (proto=="IPv6"){
            ip=6
            speedvalue = await page.$eval('#finalResultsIPv6-download-value', el => el.innerText)
            ulspeedvalue = await page.$eval('#finalResultsIPv6-upload-value', el =>el.innerText)
            latency = await page.$eval('#finalResultsIPv6-latency-value', el=>el.innerText)
        }else{
            speedvalue = await page.$eval('#finalResultsIPv4-download-value', el => el.innerText)
            ulspeedvalue = await page.$eval('#finalResultsIPv4-upload-value', el =>el.innerText)
            latency = await page.$eval('#finalResultsIPv4-latency-value', el=>el.innerText)
        }
        */
        const latency = await page.$eval('#latency', el=>el.innerText)
        .catch((err)=>{
            fs.writeFileSync(errorfile,"Error latency");
            fs.writeFileSync(errorfile,err);
            page.screenshot({path: printerrname})
           });
        const jitter= await page.$eval('#jitter', el=>el.innerText)
        .catch((err)=>{
            fs.writeFileSync(errorfile,"Error jitter");
            fs.writeFileSync(errorfile,err);
            page.screenshot({path: printerrname})
           });
        const serverloc = await page.$eval('.address', el=>el.innerText)
        .catch((err)=>{
            fs.writeFileSync(errorfile,"Error address");
            fs.writeFileSync(errorfile,err);
            page.screenshot({path: printerrname})
           });
        const dlunit = await page.$eval('#download-speed-units', el=>el.innerText)
        .catch((err)=>{
            fs.writeFileSync(errorfile,"Error dlunit");
            fs.writeFileSync(errorfile,err);
            page.screenshot({path: printerrname})
           });
        const ulunit = await page.$eval('#upload-speed-units', el=>el.innerText)
        .catch((err)=>{
            fs.writeFileSync(errorfile,"Error ulunit");
            fs.writeFileSync(errorfile,err);
            page.screenshot({path: printerrname})
           });
        var adjspeedvalue = speedvalue
        if (typeof dlunit != "undefined"){
            if (dlunit.toLowerCase()=="kbps"){
                adjspeedvalue = speedvalue/1000
            }
        }

        var adjulspeedvalue = ulspeedvalue
        if (typeof ulunit != "undefined"){
            if (ulunit.toLowerCase()=="kbps"){
                adjulspeedvalue = ulspeedvalue/1000
            }
        }
        let jv = jitter.split(" ")
        var jittervalue = jv[0] 
     /*        console.log("latency"+latency)
        console.log("server:"+serverloc)
        console.log("dl speed"+adjspeedvalue)
        console.log("ul speed"+adjulspeedvalue)
        */
        await page.tracing.stop()
        await browser.close();
        let resultstring = adjspeedvalue+";"+adjulspeedvalue+";"+latency+";"+jittervalue+";"+serverloc;
        fs.writeFileSync(tracename+".web.csv",resultstring)
    }
)()
