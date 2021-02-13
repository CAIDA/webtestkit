'use strict';
const puppeteer = require('puppeteer');
const fs = require('fs')
var tracename = "ooklaForEuro";
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
        console.log("ookla test:"+tracejson);
        const browser = await puppeteer.launch({headless: true, args: [keyarg, netlogarg]});

        // const browser = await puppeteer.launch()
        const page = await browser.newPage()
        await page.setViewport({width: 1240, height:1024})
        //await page.tracing.start({path: 'trace.json', categories: ['devtools.timeline']})
        //        await page.tracing.start({path: tracejson})
        await page.tracing.start({path: tracejson, categories: ['devtools.timeline','blink.user_timing']})
    
        await page.goto('https://www.speedtest.net')
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error goto");
                fs.writeFileSync(errorfile,err);
                page.screenshot({path: printerrname})
            });
            await page.waitFor(2000);
            var euro = true;
         
            await page.$('#_evidon-banner-content').catch((err)=>{
                euro = false;
            });
    
            console.log('check euro user:'+euro);
            if(euro){
                await page.waitForSelector('#_evidon-banner-acceptbutton', {visible: true, timeout: globaltimeout})
                .catch((err) => {
                });

                await page.click('#_evidon-banner-acceptbutton').catch((err)=>{
                    console.log(err);
                });
            }

            await page.click('.start-text')
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error start");
                fs.writeFileSync(errorfile, err);
                page.screenshot({path: printerrname})
            });

            await page.waitForSelector('a[href^="/result/"]', {visible: true, timeout: globaltimeout})
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error while jump to result");
                fs.writeFileSync(errorfile, err);
                page.screenshot({path: printerrname});
            });

        
        await page.screenshot({path: printscnname});

        const speedvalue = await page.$eval('.download-speed', el => el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error speedvalue");
                fs.writeFileSync(errorfile,err);
            });
        const ulspeedvalue = await page.$eval('.upload-speed', el =>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error ulspeedvalue");
                fs.writeFileSync(errorfile,err);
            });
        const ulatency = await page.$eval('.ping-speed', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error ulatency");
                fs.writeFileSync(errorfile,err);
            });
        const serverisp = await page.$eval('.hostUrl', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error serverisp");
                fs.writeFileSync(errorfile,err);
            });
        const serverloc = await page.$eval('.result-data .name', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error serverloc");
                fs.writeFileSync(errorfile,err);
            });
        const resultid = await page.$eval('a[href^="/result/"]', el=>el.innerText)
            .catch((err)=>{
                fs.writeFileSync(errorfile,"Error resultid");
                fs.writeFileSync(errorfile,err);
            });
    
        let resultstring = speedvalue+";"+ulspeedvalue+";"+ulatency+";"+serverloc+";"+serverisp+";"+resultid;
        fs.writeFileSync(tracename+".web.csv",resultstring);
        await page.tracing.stop()
        await browser.close();
    }
)()
