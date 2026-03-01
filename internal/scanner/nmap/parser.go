package nmap

import (
	"encoding/json"
	"encoding/xml"
	"strconv"

	"github.com/aibbp/aibbp/internal/models"
)

// XML structures for nmap output parsing.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Address  nmapAddress  `xml:"address"`
	Hostname []nmapHName  `xml:"hostnames>hostname"`
	Ports    []nmapPort   `xml:"ports>port"`
	Status   nmapStatus   `xml:"status"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHName struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	PortID   int         `xml:"portid,attr"`
	Protocol string      `xml:"protocol,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel  string `xml:"tunnel,attr"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// ParseNmapXML parses nmap XML output into ScanResults.
func ParseNmapXML(data []byte) []models.ScanResult {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}

	var results []models.ScanResult

	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}

		hostname := host.Address.Addr
		if len(host.Hostname) > 0 {
			hostname = host.Hostname[0].Name
		}

		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}

			version := port.Service.Product
			if port.Service.Version != "" {
				version += " " + port.Service.Version
			}

			scriptOutput := make(map[string]string)
			for _, script := range port.Scripts {
				scriptOutput[script.ID] = script.Output
			}

			extra, _ := json.Marshal(map[string]any{
				"service_name": port.Service.Name,
				"version":      version,
				"tunnel":       port.Service.Tunnel,
				"scripts":      scriptOutput,
				"ip":           host.Address.Addr,
			})

			results = append(results, models.ScanResult{
				Type:     "port",
				Host:     hostname,
				IP:       host.Address.Addr,
				Port:     port.PortID,
				Protocol: port.Protocol,
				Title:    port.Service.Name + " " + version,
				Extra:    extra,
			})
		}
	}

	return results
}

// portToString converts port number to string
func portToString(port int) string {
	return strconv.Itoa(port)
}
