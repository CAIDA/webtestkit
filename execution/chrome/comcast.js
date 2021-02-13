'use strict';
console.log(`Current directory: ${process.cwd()}`);
const puppeteer = require('puppeteer');
const fs = require('fs');
var tracename = "comcast";
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
    .option('-host, --host <string>', 'a string argument')
    .option('-ip, --ip <n>', 'input a integet argument.', parseInt)
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
        console.log("comcast:" + tracejson);
        // {headless: true}
        const browser = await puppeteer.launch({ headless: true , args: [keyarg, netlogarg] });
        // const browser = await puppeteer.launch();
        const page = await browser.newPage();
        await page.setViewport({ width: 1240, height: 1024 });

        //   , categories: ['devtools.timeline', 'blink.user_timing']
        await page.tracing.start({ path: tracejson, categories: ['devtools.timeline', 'blink.user_timing'] })

        await page.goto('https://speedtest.xfinity.com', { timeout: globaltimeout, waitUntil: 'networkidle0' })
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error goto");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });
        await page.waitForSelector('#app > div.container.p-3.pb-9 > div > div > div > button')
            .catch((err) => {
                console.log(err);
                fs.writeFileSync(errorfile, "Wait button error");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        if (program.host) {

            await page.click('button.block > svg:nth-child(1)')
                .catch((err) => {
                    console.log(err);
                    fs.writeFileSync(errorfile, "Error start");
                    fs.writeFileSync(errorfile, err);
                    page.screenshot({ path: printerrname })
                });

            await page.waitForSelector('div.absolute:nth-child(1)>div.mb-1', { visible: true, timeout: globaltimeout })
                .catch((err) => {
                    fs.writeFileSync(errorfile, "Error while jump to result");
                    fs.writeFileSync(errorfile, err);
                    page.screenshot({ path: printerrname });
                });

            await page.click('div.absolute:nth-child(1)>div.mb-1')
                .catch((err) => {
                    console.log(err);
                    fs.writeFileSync(errorfile, "Error click option");
                    fs.writeFileSync(errorfile, err);
                    page.screenshot({ path: printerrname })
                });

            const text = await page.$eval('#advanced-settings-host', el => el.innerText);
            const hosts = text.split(/[\r\n]/);

            var match = false;
            var hostname = undefined;
            for (var value of hosts) {
                // console.log(value);
                if (value.toUpperCase().indexOf(program.host.toUpperCase()) != -1) {
                    console.log("match, host name =" + value);
                    hostname = value;
                    match = true;
                    break;
                }
            }
            if (!match) {
                console.log("No such host");
                await page.tracing.stop();
                await browser.close();
            }

            await page.select('#advanced-settings-host', hostname);
            await page.waitFor(2000);

            await page.click('button.btn--rounded:nth-child(1)')
                .catch((err) => {
                    console.log(err);
                    fs.writeFileSync(errorfile, "Error select option");
                    fs.writeFileSync(errorfile, err);
                    page.screenshot({ path: printerrname })
                });

        } else {
            // #app > div.container.p-3.pb-9 > div > div > div > button
            // TODO
            await page.click('#app > div.container.p-3.pb-9 > div > div > div > button')
                .catch((err) => {
                    console.log(err);
                    fs.writeFileSync(errorfile, "Error start");
                    fs.writeFileSync(errorfile, err);
                    page.screenshot({ path: printerrname })
                });
        }


        await page.waitForSelector('div.flex-col:nth-child(3)', { visible: true, timeout: globaltimeout })
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error while jump to result");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname });
            });

        await page.click('summary.relative > div:nth-child(1)')
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error Show more");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        /*
        the upload speed calculation is very distinctive 
        so first wait until the element loacted 
        then wait until it remove from dom
        */

        await page.waitForXPath('//*[@id="app"]/div[2]/details/div/div/dl/div[1]/dd/div/span', { visible: true })
            .catch((err) => {
            });

        await page.waitForXPath('//*[@id="app"]/div[2]/details/div/div/dl/div[1]/dd/div/span', { hidden: true })
            .catch((err) => {
            });

        await page.screenshot({ path: printscnname }).catch((e)=>{console.log("print screen error",e)});

        const latency = await page.$eval('div.justify-between:nth-child(2) > dd:nth-child(2)', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error latency");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        const uploadspeedtemp = await page.$eval('div.pb-4:nth-child(1) > dd:nth-child(2)', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error uploadspeedtemp");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        const protocoal = await page.$eval('div.justify-between:nth-child(3) > dd:nth-child(2)', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error proto");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        const host = await page.$eval('div.flex:nth-child(4) > dd:nth-child(2)', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error host");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        const downloadspeedtemp = await page.$eval('summary.relative > div:nth-child(1) > dl > dd', el => el.innerText)
            .catch((err) => {
                fs.writeFileSync(errorfile, "Error downloadspeedtemp");
                fs.writeFileSync(errorfile, err);
                page.screenshot({ path: printerrname })
            });

        let index = downloadspeedtemp.indexOf('bps') - 1;
        let units = downloadspeedtemp.substr(index);
        var downloadspeed = downloadspeedtemp.substr(0, index);
        if (units.toLowerCase() == "kbps") {
            downloadspeed = Number(speedvalue) / 1000;
        }

        var upltem = uploadspeedtemp.split(" ");
        var uploadspeed = upltem[0];
        if (upltem[1].toLowerCase() == "kbps") {
            uploadspeed = Number(upltem[0]) / 1000;
        }


        let resultstring = downloadspeed + ";" + uploadspeed + ";" + latency + ";" + protocoal + ";" + host;

        console.log(resultstring);

        try {
            fs.writeFileSync(tracename + ".web.csv", resultstring);
        } catch (err) {
            fs.writeFileSync(errorfile, "Error orrurs while writing file");
        }
        await page.tracing.stop()
        await browser.close();
    }
)()
