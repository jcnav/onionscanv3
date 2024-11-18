package protocol

import (
	"github.com/Chiranjeevi/onionscan/config"
	"github.com/Chiranjeevi/onionscan/report"
)

type Scanner interface {
	ScanProtocol(hiddenService string, onionscanConfig *config.OnionScanConfig, report *report.OnionScanReport)
}
