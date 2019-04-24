// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package h2sidecar

import (
	"errors"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"

	http_conn "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/plugin"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pkg/log"
)

// Plugin instructs sidecars to speak h2 to matching ports.
type Plugin struct{}

// NewPlugin returns an instance of the h2sidecar plugin.
func NewPlugin() plugin.Plugin {
	return Plugin{}
}

// OnOutboundListener is called whenever a new outbound listener is added to the LDS output for a given service
// Can be used to add additional filters on the outbound path
func (Plugin) OnOutboundListener(in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	if in.Node == nil {
		return nil
	}

	if in.Node.Type != model.SidecarProxy {
		return nil
	}

	if in.ListenerCategory != networking.EnvoyFilter_ListenerMatch_SIDECAR_OUTBOUND {
		return nil
	}

	if mutable == nil {
		return nil
	}

	if in.Port == nil {
		return nil
	}

	if in.Port.Port != 10443 {
		return nil
	}

	// TODO: Restrict port name?

	if len(mutable.FilterChains) < 1 {
		log.Infof("h2sidecar: OnInboundListener: Expected at least 1 listeners in filterchain %v", mutable)
		return nil
	}

	filterChain := mutable.FilterChains[0]
	if len(filterChain.TCP) < 1 {
		log.Infof("h2sidecar: OnInboundListener: Expected at least 1 listener in filterchain filters %v", mutable)
		return nil
	}
	httpConnectionManagerFilter := filterChain.TCP[0]
	newFilterChain := buildFilterChain(httpConnectionManagerFilter)
	mutable.FilterChains = append(mutable.FilterChains, *newFilterChain)

	return nil
}

// OnInboundListener is called whenever a new listener is added to the LDS output for a given service
// Can be used to add additional filters (e.g., mixer filter) or add more stuff to the HTTP connection manager
// on the inbound path
func (Plugin) OnInboundListener(in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	return nil
}

// setListenerH2S configures an listener to talk H2S.
// TLC certs are hardcoded and ALPN is H2 only.
func setListenerH2S(index int, mutable *plugin.MutableObjects) error {
	if len(mutable.FilterChains) < index+1 {
		log.Infof("h2sidecar: Expected at least %v listeners in filterchain %v", index+1, mutable)
		return errors.New("Too few listeners")
	}

	for ix, filterChain := range mutable.FilterChains {
		log.Infof("h2sidecar: filterchain index %v is %v", ix, filterChain)
	}

	// 0 index is expected to be the mtlschain
	filterChain := mutable.FilterChains[index]
	log.Infof("h2sidecar: Mutating listener filterChain %v", filterChain)

	if filterChain.TLSContext == nil {
		log.Infof("h2sidecar: TLSContext was nil")
		filterChain.TLSContext = &auth.DownstreamTlsContext{}
	}

	if filterChain.TLSContext.CommonTlsContext == nil {
		log.Infof("h2sidecar: CommonTLSContext was nil")
		filterChain.TLSContext.CommonTlsContext = &auth.CommonTlsContext{}
	}

	// TODO: Should be configured to value set in destinationrule rather than hardcoded.
	filterChain.TLSContext.CommonTlsContext.TlsCertificates = []*auth.TlsCertificate{
		{CertificateChain: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/certs/tls.crt"}},
			PrivateKey: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/certs/tls.key"}},
		},
	}

	// Only accept h2 on this listener.
	filterChain.TLSContext.CommonTlsContext.AlpnProtocols = util.ALPNH2Only

	// Match on h2 tls
	if filterChain.FilterChainMatch == nil {
		filterChain.FilterChainMatch = &listener.FilterChainMatch{}
	}
	filterChain.FilterChainMatch.TransportProtocol = "tls"
	filterChain.FilterChainMatch.ApplicationProtocols = []string{"h2"}

	log.Infof("h2sidecar: mutated filterchain to %v", filterChain)
	mutable.FilterChains[index] = filterChain
	return nil
}

// build a filterChain copy-pasteing a given httpConnectionManager.
func buildFilterChain(httpConnectionManager listener.Filter) *plugin.FilterChain {
	return &plugin.FilterChain{
		FilterChainMatch: &listener.FilterChainMatch{
			TransportProtocol:    "tls",
			ApplicationProtocols: []string{"h2"},
		},

		TLSContext: &auth.DownstreamTlsContext{
			CommonTlsContext: &auth.CommonTlsContext{
				TlsCertificates: []*auth.TlsCertificate{
					{CertificateChain: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/certs/tls.crt"}},
						PrivateKey: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/certs/tls.key"}},
					},
				},
			},
		},

		ListenerFilters: []listener.ListenerFilter{
			listener.ListenerFilter{
				Name: "envoy.listener.tls_inspector",
			},
		},

		ListenerProtocol: plugin.ListenerProtocolHTTP,

		HTTP: []*http_conn.HttpFilter{
			&http_conn.HttpFilter{
				Name: "envoy.router",
			},
		},

		TCP: []listener.Filter{httpConnectionManager},
	}
}

// OnInboundCluster implements the Plugin interface method.
func (Plugin) OnInboundCluster(in *plugin.InputParams, cluster *xdsapi.Cluster) {
	if in.Node == nil {
		return
	}

	if in.Node.Type != model.SidecarProxy {
		return
	}

	if in.ServiceInstance == nil {
		return
	}

	if cluster == nil {
		return
	}

	if in.Port == nil {
		return
	}

	if in.Port.Port != 10443 {
		return
	}

	setClusterALPNH2(cluster)
	log.Infof("h2sidecar: Writing h2 cluster: %v", cluster)
}

// setClusterALPNH2 sets ALPN protocols to "H2" in the clusters tls context.
func setClusterALPNH2(cluster *xdsapi.Cluster) {
	if cluster.TlsContext == nil {
		cluster.TlsContext = &auth.UpstreamTlsContext{}
	}

	if cluster.TlsContext.CommonTlsContext == nil {
		cluster.TlsContext.CommonTlsContext = &auth.CommonTlsContext{}
	}

	cluster.TlsContext.CommonTlsContext.AlpnProtocols = util.ALPNH2Only
}

// OnOutboundRouteConfiguration implements the Plugin interface method.
func (Plugin) OnOutboundRouteConfiguration(in *plugin.InputParams, route *xdsapi.RouteConfiguration) {
	if in.Node == nil {
		log.Infof("h2sidecar: OnOutboundRoute: No node. Skipping %v %v", in, route)
		return
	}

	if in.Node.Type != model.SidecarProxy {
		log.Infof("h2sidecar: OnOutboundRoute: Node type not SidecarProxy. Skipping %v %v", in, route)
		return
	}

	if in.ListenerCategory != networking.EnvoyFilter_ListenerMatch_SIDECAR_OUTBOUND {
		log.Infof("h2sidecar: OnOutboundRoute: Listener category not SidecarOutbound. Skipping %v %v", in, route)
		return
	}

	if in.ServiceInstance == nil {
		log.Infof("h2sidecar: OnOutboundRoute: No ServiceInstance. Skipping %v %v", in, route)
		return
	}

	if route == nil {
		log.Infof("h2sidecar: OnOutboundRoute: No route. Skipping %v %v", in, route)
		return
	}

	if in.Port == nil {
		log.Infof("h2sidecar: OnOutboundRoute: No Port. Skipping %v %v", in, route)
		return
	}

	if in.Port.Port != 10443 {
		log.Infof("h2sidecar: OnOutboundRoute: Port not 10443. Skipping %v %v", in, route)
		return
	}

	if in.Port.Name != "http2-elements" && in.Port.Name != "https-elements" {
		log.Infof("h2sidecar: OnOutboundRoute: Port name not http2-elements or https-elements. Skipping %v %v", in, route)
		return
	}

	// TODO:
	log.Infof("h2sidecar: OnOutboundRoute: Manipulating %v %v", in, route)
}

// OnInboundRouteConfiguration implements the Plugin interface method.
func (Plugin) OnInboundRouteConfiguration(in *plugin.InputParams, route *xdsapi.RouteConfiguration) {
	if in.Node == nil {
		log.Infof("h2sidecar: OnInboundRoute: No node. Skipping %v %v", in, route)
		return
	}

	if in.Node.Type != model.SidecarProxy {
		log.Infof("h2sidecar: OnInboundRoute: Node type not SidecarProxy. Skipping %v %v", in, route)
		return
	}

	if in.ListenerCategory != networking.EnvoyFilter_ListenerMatch_SIDECAR_INBOUND {
		log.Infof("h2sidecar: OnInboundRoute: Listener category not SidecarInbound. Skipping %v %v", in, route)
		return
	}

	if route == nil {
		log.Infof("h2sidecar: OnInboundRoute: No route. Skipping %v %v", in, route)
		return
	}

	if in.Port == nil {
		log.Infof("h2sidecar: OnInboundRoute: No Port. Skipping %v %v", in, route)
		return
	}

	if in.Port.Port != 10443 {
		log.Infof("h2sidecar: OnInboundRoute: Port not 10443. Skipping %v %v", in, route)
		return
	}

	// TODO:
	log.Infof("h2sidecar: OnInboundRoute: Manipulating %v %v", in, route)
}

// OnOutboundCluster implements the Plugin interface method.
func (Plugin) OnOutboundCluster(in *plugin.InputParams, cluster *xdsapi.Cluster) {
}

// OnInboundFilterChains is called whenever a plugin needs to setup the filter chains, including relevant filter chain configuration.
func (Plugin) OnInboundFilterChains(in *plugin.InputParams) []plugin.FilterChain {
	if in.Node == nil {
		log.Infof("h2sidecar: OnInboundFilterChains: No node. Skipping %v", in)
		return nil
	}

	if in.Node.Type != model.SidecarProxy {
		log.Infof("h2sidecar: OnInboundFilterChains: Node type not SidecarProxy. Skipping %v", in)
		return nil
	}

	if in.ListenerCategory != networking.EnvoyFilter_ListenerMatch_SIDECAR_INBOUND {
		log.Infof("h2sidecar: OnInboundFilterChains: Listener category not SidecarInbound. Skipping %v", in)
		return nil
	}

	if in.ServiceInstance == nil {
		log.Infof("h2sidecar: OnInboundFilterChains: No ServiceInstance. Skipping %v", in)
		return nil
	}

	if in.Port == nil {
		log.Infof("h2sidecar: OnInboundFilterChains: No Port. Skipping %v", in)
		return nil
	}

	if in.Port.Port != 10443 {
		log.Infof("h2sidecar: OnInboundFilterChains: Port not 10443. Skipping %v", in)
		return nil
	}

	// TODO:
	log.Infof("h2sidecar: OnInboundFilterChains: Manipulating %vv", in)
	return nil
}
