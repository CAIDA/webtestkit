'use strict';

const puppeteer = require('puppeteer');
const fs = require('fs');
var tracename = "cloudflare";
//console.log(process.argv.length)
if (process.argv.length >= 3) {
    tracename = process.argv[2];
}
var globaltimeout = 120000;
(
    async () => {
        var tracejson = "./result/" + tracename + ".json";
        var errorfile = "./result/" + tracename + ".err";
        var printscnname = "./result/" + tracename + ".png";
        var printerrname = "./result/" + tracename + ".err.png";
        var keyarg = "--ssl-key-log-file=./"+tracename+".key";
        console.log("speedofme:" + tracejson);
        const browser = await puppeteer.launch({ headless: true ,args: [keyarg]})
        const page = await browser.newPage()
        // await page.setViewport({width: 1240, height:1024})

        console.log(tracejson);

        //await page.tracing.start({path: 'trace.json', categories: ['devtools.timeline']})
        await page.tracing.start({ path: tracejson, categories: ['devtools.timeline', 'blink.user_timing'] })
        //await page.tracing.start({path: tracejson})
        await page.goto('https://speed.cloudflare.com/')
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error goto");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });


        await page.waitForSelector('button.react-share__ShareButton:nth-child(3) > div:nth-child(1)', { timeout: globaltimeout })
            .catch((err) => {
                fs.writeFileSync(errorfile, "Jump to result");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });
        
        await page.waitForTimeout(1000);

        await page.screenshot({ path: printscnname });

        let download = await page.evaluate(() => document.evaluate('//*[@id="__next"]/div/div/div[1]/div[5]/div[1]/div[2]/div/div[2]/div[1]/div/div[3]/div[1]', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.innerText);

        // let download = await page.evaluate(() =>);

        let upload = await page.evaluate(() =>document.evaluate('//*[@id="__next"]/div/div/div[1]/div[5]/div[1]/div[2]/div/div[2]/div[2]/div/div[1]/div[3]/div[1]', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.innerText)
        
        let latency = await page.evaluate(() =>document.evaluate('//*[@id="__next"]/div/div/div[1]/div[5]/div[1]/div[2]/div/div[2]/div[2]/div/div[3]/div[3]/div[1]', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.innerText);

        let jitter = await page.evaluate(() =>document.evaluate('//*[@id="__next"]/div/div/div[1]/div[5]/div[1]/div[2]/div/div[2]/div[2]/div/div[3]/div[8]/div[1]', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.innerText);

        let location = await page.evaluate(() =>document.evaluate('//*[@id="__next"]/div/div/div[1]/div[5]/div[3]/div[2]/div/div[2]/div[2]/div[2]/span', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.innerText);

        let ip = await page.evaluate(() =>document.evaluate('//*[@id="__next"]/div/div/div[1]/div[5]/div[3]/div[2]/div/div[2]/div[3]/div[2]/span', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.innerText);

        console.log(download)
        console.log(upload)
        console.log(latency)
        console.log(jitter)
        console.log(location)
        console.log(ip)



        try {
            let resultstring = download + ";" + upload + ";" + latency + ";" + jitter + ";" + location + ";" + ip;
            console.log(resultstring);
            fs.writeFileSync("./result/"+tracename + ".web.csv", resultstring);
        } catch (err) {
            fs.writeFileSync(errorfile, "Error parsing result");
            fs.writeFileSync(errorfile, summaryok);
        }

        
        await page.tracing.stop()
        await browser.close();
    }
)()