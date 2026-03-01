package queue

// NATS JetStream subject constants.
const (
	// Stream names
	StreamScans   = "SCANS"
	StreamTasks   = "TASKS"
	StreamResults = "RESULTS"
	StreamEvents  = "EVENTS"

	// Task subjects - scanner worker subscribes to these
	SubjectTaskScan       = "tasks.scan.>"          // tasks.scan.{scanner_type}
	SubjectTaskScanNmap   = "tasks.scan.nmap"
	SubjectTaskScanNuclei = "tasks.scan.nuclei"
	SubjectTaskScanHTTPX  = "tasks.scan.httpx"
	SubjectTaskScanSub    = "tasks.scan.subfinder"
	SubjectTaskScanMass   = "tasks.scan.masscan"
	SubjectTaskScanFfuf   = "tasks.scan.ffuf"
	SubjectTaskScanKatana = "tasks.scan.katana"
	SubjectTaskScanDNSX   = "tasks.scan.dnsx"
	SubjectTaskScanGowit  = "tasks.scan.gowitness"

	// Preprocessor subjects
	SubjectTaskPreprocess = "tasks.preprocess"

	// AI brain subjects
	SubjectTaskAnalyze  = "tasks.analyze.>"
	SubjectTaskValidate = "tasks.validate"

	// Scan result subjects
	SubjectScanResultRaw          = "scan.results.raw"
	SubjectScanResultPreprocessed = "scan.results.preprocessed"

	// Event subjects
	SubjectEventScanStatus      = "events.scan.status"
	SubjectEventVulnFound       = "events.vuln.found"
	SubjectEventBudgetUpdate    = "events.budget.update"
	SubjectEventPhaseTransition = "events.phase.transition"

	// Active testing subjects
	SubjectActiveTestTask   = "active.test.task"
	SubjectActiveTestResult = "active.test.result"
	SubjectActiveTestStatus = "active.test.status"
	SubjectActiveTestKill   = "active.test.kill"

	// Consumer group names
	ConsumerScanWorker    = "scan-worker"
	ConsumerPreprocessor  = "preprocess-worker"
	ConsumerAIBrain       = "ai-brain"
	ConsumerEventLogger   = "event-logger"
	ConsumerActiveTester  = "active-tester"
)

// TaskScanSubject returns the subject for a specific scanner type.
func TaskScanSubject(scannerType string) string {
	return "tasks.scan." + scannerType
}
