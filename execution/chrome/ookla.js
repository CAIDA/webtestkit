'use strict';
const puppeteer = require('puppeteer');
const fs = require('fs')
var tracename = "ookla";
var program = require('commander');


//console.log(process.argv.length)
if (process.argv.length >= 3) {
    tracename = process.argv[2];
}
/*************************** */
function range(val) {
    return val.split('..').map(Number);
}

function list(val) {
    return val.split(',')
}

program
    .version('0.0.1')
    .usage('[options] [value ...]')
    .option('-city, --city <string>', 'a string argument')
    .option('-net, --net <string>', 'a string argument')
// .option('-f, --float <f>', 'input a float arg', parseFloat)
// .option('-l, --list <items>', 'a list', list)
// .option('-r, --range <a>..<b>', 'a range', range)

program.on('help', function () {
    console.log('   Examples:')
    console.log('')
    console.log('       # input string, integer and float')
    console.log('       $ ./nodecmd.js -m \"a string\" -i 1 -f 1.01')
    console.log('')
    console.log('       # input range 1 - 3')
    console.log('       $ ./nodecmd.js -r 1..3')
    console.log('')
    console.log('       # input list: [1,2,3]')
    console.log('       $ ./nodecmd.js -l 1,2,3')
    console.log('')
});
program.parse(process.argv)

/*************************** */


var globaltimeout = 120000;
(
    async () => {
        var tracejson = "./" + tracename + ".json";
        var errorfile = "./" + tracename + ".err";
        var printscnname = "./" + tracename + ".png";
        var printerrname = "./" + tracename + ".err.png";

        var keyarg = "--ssl-key-log-file=./"+tracename+".key";
        var netlogarg = "--log-net-log=./"+tracename+".netlog";
        console.log("ookla test:" + tracejson);
        const browser = await puppeteer.launch({ headless: true , args: [keyarg, netlogarg] })
        const page = await browser.newPage()
        await page.setViewport({ width: 1240, height: 1024 })
        //await page.tracing.start({path: 'trace.json', categories: ['devtools.timeline']})
        //        await page.tracing.start({path: tracejson})

        await page.tracing.start({ path: tracejson, categories: ['devtools.timeline', 'blink.user_timing'] })
        await page.goto('https://www.speedtest.net')
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error goto");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });
        await page.waitFor(3000);


        if (program.city && program.net) {
            var cityname = program.city.replace(/_/g, ' ');
            // cityname.replace("_"," ");
            var netname = program.net.replace(/_/g, ' ');
            // netname.replace("_"," ");
            console.log(cityname);
            console.log(netname);

            await page.click('div.pure-u-5-12:nth-child(3) > div:nth-child(1) > div:nth-child(1) > div:nth-child(4) > a:nth-child(1)')
                .catch((err) => {
                    fs.writeFileSync(errorfile, "Error change server");
                    fs.writeFileSync(errorfile, err);
                    page.screenshot({ path: printerrname })
                });

            await page.waitForSelector('#host-search')
                .catch((err) => {
                    console.log(err);
                    fs.writeFileSync(errorfile, "Wait input");
                    fs.writeFileSync(errorfile, err);
                    page.screenshot({ path: printerrname })
                });


            await page.type('#host-search', cityname);
            await page.waitFor(2000);

            // const datatext = await page.evaluate(() => {
            //     const tds = Array.from(document.querySelectorAll('.server-hosts-list'))
            //     return tds.map(td => td.innerText)
            //   });
            const datatext = await page.$eval('.server-hosts-list', el => el.innerText);
            const datalist = datatext.split(/[\r\n]/);
            //   .server-hosts-list > ul:nth-child(2) > li:nth-child(1)
            var count = 0;
            var match = false;
            for (var data of datalist) {
                count++;
                if (data.toUpperCase().indexOf(netname.toUpperCase()) != -1) {
                    console.log("match,server name=" + data);
                    match = true;
                    break;
                }
            }
            if (match) {
                // .server-hosts-list > ul:nth-child(2) > li:nth-child(3) > a:nth-child(1)
                var selector1 = ".server-hosts-list > ul:nth-child(2) > li:nth-child(" + count + ")";
                console.log(selector1);
                await page.click(selector1)
                    .catch((err) => {
                        fs.writeFileSync(errorfile, "Error start");
                        fs.writeFileSync(errorfile, err);
                        page.screenshot({ path: printerrname })
                    });
            }else{
                console.log("No such a server");
                await page.tracing.stop()
                await browser.close();
            }
        }
        //TODO
        await page.click('.start-text')
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error start");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        // await page.waitForNavigation({waitUntil:"load",timeout:globaltimeout});
        await page.waitForSelector('a[href^="/result/"]', { visible: true, timeout: globaltimeout })
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error while jump to result");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname });
            });

        await page.screenshot({ path: printscnname });

        const speedvalue = await page.$eval('.download-speed', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error speedvalue");
                fs.writeFileSync(errorfile, err);
            });
        const ulspeedvalue = await page.$eval('.upload-speed', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error ulspeedvalue");
                fs.writeFileSync(errorfile, err);
            });
        const ulatency = await page.$eval('.ping-speed', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error ulatency");
                fs.writeFileSync(errorfile, err);
            });
        const serverisp = await page.$eval('.hostUrl', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error serverisp");
                fs.writeFileSync(errorfile, err);
            });
        const serverloc = await page.$eval('.result-data .name', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error serverloc");
                fs.writeFileSync(errorfile, err);
            });
        const resultid = await page.$eval('a[href^="/result/"]', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error resultid");
                fs.writeFileSync(errorfile, err);
            });

        let resultstring = speedvalue + ";" + ulspeedvalue + ";" + ulatency + ";" + serverloc + ";" + serverisp + ";" + resultid;
        console.log(resultstring);
        fs.writeFileSync(tracename + ".web.csv", resultstring);
        await page.tracing.stop()
        await browser.close();
    }
)()