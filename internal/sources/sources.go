package sources

import (
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/config"
)

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

type Resolver struct {
	store *config.SourceStore
}

var defaultResolver *Resolver

func NewResolver(store *config.SourceStore) *Resolver {
	return &Resolver{store: store}
}

func SetDefaultResolver(r *Resolver) {
	defaultResolver = r
}

func (r *Resolver) Resolve(ip, host, app, message string) SourceInfo {
	if r == nil || r.store == nil {
		return r.resolveFallback(ip, host, app, message)
	}
	for _, src := range r.store.All() {
		if src.Enabled && src.IP == ip {
			return SourceInfo{AssetName: src.Name, SourceType: src.Type, AssetIP: src.IP}
		}
	}
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

func (r *Resolver) Known() map[string]SourceInfo {
	if r == nil || r.store == nil {
		out := make(map[string]SourceInfo, len(assetByIP))
		for k, v := range assetByIP {
			out[k] = v
		}
		return out
	}
	all := r.store.All()
	out := make(map[string]SourceInfo, len(all))
	for _, s := range all {
		out[s.IP] = SourceInfo{
			AssetName:  s.Name,
			SourceType: s.Type,
			AssetIP:    s.IP,
		}
	}
	return out
}

func Resolve(ip, host, app, message string) SourceInfo {
	if defaultResolver != nil {
		return defaultResolver.Resolve(ip, host, app, message)
	}
	return (&Resolver{store: nil}).resolveFallback(ip, host, app, message)
}

func Known() map[string]SourceInfo {
	if defaultResolver != nil {
		return defaultResolver.Known()
	}
	out := make(map[string]SourceInfo, len(assetByIP))
	for k, v := range assetByIP {
		out[k] = v
	}
	return out
}

func (r *Resolver) resolveFallback(ip, host, app, message string) SourceInfo {
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
