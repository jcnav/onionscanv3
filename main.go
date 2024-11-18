package main

import (
	"flag"
	"github.com/Chiranjeevi/onionscan/config"
	"github.com/Chiranjeevi/onionscan/deanonymization"
	"github.com/Chiranjeevi/onionscan/onionscan"
	"github.com/Chiranjeevi/onionscan/onionscan/steps"
	"github.com/Chiranjeevi/onionscan/report"
	"github.com/Chiranjeevi/onionscan/utils"
	"github.com/Chiranjeevi/onionscan/webui"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func main() {
    // Define and parse flags
    torProxyAddress := flag.String("torProxyAddress", "127.0.0.1:9050", "the address of the tor proxy to use")
    simpleReport := flag.Bool("simpleReport", true, "print out a simple report detailing what is wrong and how to fix it, true by default")
    jsonSimpleReport := flag.Bool("jsonSimpleReport", false, "print out a simple report as json, false by default")
    reportFile := flag.String("reportFile", "", "the file destination path for report file - if given, the prefix of the file will be the scanned onion service. If not given, the report will be written to stdout")
    jsonReport := flag.Bool("jsonReport", false, "print out a json report providing a detailed report of the scan.")
    verbose := flag.Bool("verbose", false, "print out a verbose log output of the scan")
    directoryDepth := flag.Int("depth", 100, "depth of directory scan recursion (default: 100)")
    fingerprint := flag.Bool("fingerprint", true, "true disables some deeper scans e.g. directory probing with the aim of just getting a fingerprint of the service.")
    list := flag.String("list", "", "If provided OnionScan will attempt to read from the given list, rather than the provided hidden service")
    timeout := flag.Int("timeout", 120, "read timeout for connecting to onion services")
    batch := flag.Int("batch", 10, "number of onions to scan concurrently")
    dbdir := flag.String("dbdir", "./onionscandb", "The directory where the crawl database will be stored")
    crawlconfigdir := flag.String("crawlconfigdir", "", "A directory where crawl configurations are stored")
    scans := flag.String("scans", "", "a comma-separated list of scans to run e.g. web,tls,... (default: run all)")
    webport := flag.Int("webport", 8080, "if given, onionscan will expose a webserver on localhost:[port] to enabled searching of the database")
    mode := flag.String("mode", "scan", "one of scan or analysis. In analysis mode, webport must be set.")
    cookiestring := flag.String("cookie", "", "if provided, onionscan will use this cookie")

    // Parse command-line flags
    flag.Parse()

    // Validate required arguments
    if (len(flag.Args()) != 1 && *list == "") && *mode != "analysis" {
        flag.Usage()
        os.Exit(1)
    }

    // Initialize OnionScan
    onionScan := new(onionscan.OnionScan)
    var scanslist []string
    if *scans != "" {
        scanslist = strings.Split(*scans, ",")
    } else {
        scanslist = onionScan.GetAllActions()
    }

    onionScan.Config = config.Configure(*torProxyAddress, *directoryDepth, *fingerprint, *timeout, *dbdir, scanslist, *crawlconfigdir, *cookiestring, *verbose)

    // Handle "scan" mode
    if *mode == "scan" {
        if !*simpleReport && !*jsonReport && !*jsonSimpleReport {
            log.Fatalf("You must set one of --simpleReport or --jsonReport or --jsonSimpleReport in scan mode")
        }

        proxyStatus := utils.CheckTorProxy(*torProxyAddress)
        if proxyStatus != utils.ProxyStatusOK {
            log.Fatalf("%s, is the --torProxyAddress setting correct?", utils.ProxyStatusMessage(proxyStatus))
        }

        onionsToScan := []string{}
        if *list == "" {
            onionsToScan = append(onionsToScan, flag.Args()[0])
            log.Printf("Starting Scan of %s\n", flag.Args()[0])
        } else {
            content, err := ioutil.ReadFile(*list)
            if err != nil {
                log.Fatalf("Could not read onion file %s\n", *list)
            }
            onions := strings.Split(string(content), "\n")
            for _, onion := range onions {
                if onion != "" {
                    onionsToScan = append(onionsToScan, onion)
                }
            }
            log.Printf("Starting Scan of %d onion services\n", len(onionsToScan))
        }
        log.Printf("This might take a few minutes..\n\n")

        // Perform the scan
        done := make(chan bool)
        go func() {
            doScanMode(onionScan, onionsToScan, *batch, *reportFile, *simpleReport, *jsonReport, *jsonSimpleReport)
            done <- true
        }()

        <-done
        log.Printf("Scan completed. Exiting program.\n")
        os.Exit(0)
    }

    // Handle "analysis" mode with web UI
    webui := new(webui.WebUI)
    if *webport > 0 {
        go webui.Listen(onionScan.Config, *webport)
        <-webui.Done
    }
}

// doScanMode prepares a pipeline of processes this run is managing and then
// periodically sends new onions through the pipeline - no more than `batch`
// onions are processed simultaneously.
func doScanMode(onionScan *onionscan.OnionScan, onionsToScan []string, batch int, reportFile string, simpleReport bool, jsonReport bool, jsonSimpleReport bool) {
    reports := make(chan *report.OnionScanReport)

    pipeline := new(onionscan.Pipeline)
    pipeline.Init(reports)

    // Add Crawlers
    pipeline.AddStep(onionScan)

    // Extract Identifiers
    eis := new(deanonymization.ExtractIdentifierStep)
    eis.Init(onionScan.Config)
    pipeline.AddStep(eis)

    // Publish to a Sink
    if jsonReport {
        step := new(steps.JSONReportWriter)
        step.Init(reportFile)
        pipeline.AddStep(step)
    } else {
        termWidth, _, err := terminal.GetSize(int(os.Stdin.Fd()))
        if err != nil {
            termWidth = 80
        }
        step := new(steps.SimpleReportWriter)
        step.Init(reportFile, jsonSimpleReport, termWidth-1)
        pipeline.AddStep(step)
    }

    count := 0
    if batch > len(onionsToScan) {
        batch = len(onionsToScan)
    }

    // Run an initial batch of requests
    for count < batch {
        go pipeline.Execute(onionsToScan[count])
        count++
    }

    received := 0
    for received < len(onionsToScan) {
        osreport := <-reports

        if osreport.Error != nil {
            onionScan.Config.LogError(osreport.Error)
        }

        // After the initial batch, it's one in, one out to prevent proxy overload.
        if count < len(onionsToScan) {
            go pipeline.Execute(onionsToScan[count])
            count++
        }
        received++
    }

    log.Printf("All scans completed. Closing pipeline.")
}
