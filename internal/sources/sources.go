package sources

import "strings"

type SourceInfo struct {
	AssetName  string `json:"asset_name"`
	SourceType string `json:"source_type"`
	AssetIP    string `json:"asset_ip"`
}

var assetByIP = map[string]SourceInfo{
	"192.168.1.20":  {AssetName: "labshock-plc1-1", SourceType: "plc", AssetIP: "192.168.1.20"},
	"192.168.1.21":  {AssetName: "labshock-plc2-1", SourceType: "plc", AssetIP: "192.168.1.21"},
	"192.168.1.22":  {AssetName: "labshock-plc3-1", SourceType: "plc", AssetIP: "192.168.1.22"},
	"192.168.1.23":  {AssetName: "labshock-plc4-1", SourceType: "plc", AssetIP: "192.168.1.23"},
	"192.168.1.24":  {AssetName: "labshock-plc5-1", SourceType: "plc", AssetIP: "192.168.1.24"},
	"192.168.1.60":  {AssetName: "labshock_scada", SourceType: "scada", AssetIP: "192.168.1.60"},
	"192.168.1.62":  {AssetName: "powergrid_opcua_server", SourceType: "opcua", AssetIP: "192.168.1.62"},
	"192.168.1.50":  {AssetName: "labshock-ews-1", SourceType: "ews", AssetIP: "192.168.1.50"},
	"192.168.1.254": {AssetName: "ot_firewall", SourceType: "firewall", AssetIP: "192.168.1.254"},
}

func Resolve(ip, host, app, message string) SourceInfo {
	if s, ok := assetByIP[ip]; ok {
		return s
	}

	h := strings.ToLower(host + " " + app + " " + message)
	switch {
	case strings.Contains(h, "fuxa"):
		return SourceInfo{AssetName: "labshock_scada", SourceType: "scada", AssetIP: ip}
	case strings.Contains(h, "openplc"):
		return SourceInfo{AssetName: "unknown", SourceType: "plc", AssetIP: ip}
	case strings.Contains(h, "opcua") || strings.Contains(h, "powergrid_opcua_server") || strings.Contains(h, "powergrid-opcua"):
		return SourceInfo{AssetName: "powergrid_opcua_server", SourceType: "opcua", AssetIP: ip}
	default:
		return SourceInfo{AssetName: "unknown", SourceType: "unknown", AssetIP: ip}
	}
}

func Known() map[string]SourceInfo {
	out := make(map[string]SourceInfo, len(assetByIP))
	for k, v := range assetByIP {
		out[k] = v
	}
	return out
}

