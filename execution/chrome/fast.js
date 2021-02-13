'use strict';

const puppeteer = require('puppeteer');
const fs = require('fs');
var tracename = "fast";
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
        console.log("fast:"+tracejson);
        const browser = await puppeteer.launch({ headless: true , args: [keyarg, netlogarg] });
        const page = await browser.newPage();
        await page.setViewport({ width: 1240, height: 1024 });
        //        console.log(tracejson);
        //await page.tracing.start({path: 'trace.json', categories: ['devtools.timeline']})
        await page.tracing.start({path: tracejson, categories: ['devtools.timeline','blink.user_timing']})
        //await page.tracing.start({path: tracejson})
        await page.goto('https://fast.com/')
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error goto");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            });
        const speedmsg = await page.mainFrame()
            .waitForSelector('#your-speed-message',{visible: true, timeout: globaltimeout})
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error download");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
            /*    .then(async ()=>{
                const speedvalue = await page.$eval('#speed-value', el => el.innerText);
                console.log("speed done"+speedvalue);
            })*/

        await page.click('#show-more-details-link')
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error detail");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            });
        const ul = await page.mainFrame()
            .waitForSelector('.speed-progress-indicator.circle.succeeded',{timeout: globaltimeout})
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error succeeded");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        await page.screenshot({path: printscnname}).catch((e)=>{console.log(e)})
        //            .waitForSelector('.extra-measurement-result .succeeded')
        const speedvalue = await page.$eval('#speed-value', el => el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error speedvalue");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        const ulspeedvalue = await page.$eval('#upload-value', el =>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error ulspeedvalue");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        const ulatency = await page.$eval('#latency-value', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error ulatency");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        const blatency = await page.$eval('#bufferbloat-value', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error blatency");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        const serverloc = await page.$eval('#server-locations', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error serverloc");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        const dlmb = await page.$eval('#down-mb-value', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error dlmb");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        const upmb = await page.$eval('#up-mb-value', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error upmb");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        const dlunit = await page.$eval('#speed-units', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error dlunit");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
        const ulunit = await page.$eval('#upload-units', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error ulunit");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            })
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
            /*
        console.log("latency"+ulatency+","+blatency)
        console.log("server:"+serverloc)
        console.log("dl speed"+speedvalue+" "+dlunit)
        console.log("ul speed"+ulspeedvalue+" "+ulunit)
        */
        await page.tracing.stop()
        await browser.close();
        let resultstring = adjspeedvalue+";"+adjulspeedvalue+";"+ulatency+";"+blatency+";"+dlmb+";"+upmb+";"+serverloc;
        fs.writeFileSync(tracename+".web.csv",resultstring)
    }
)()
