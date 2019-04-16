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
	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"

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

	if in.ListenerCategory == networking.EnvoyFilter_ListenerMatch_SIDECAR_OUTBOUND {
		return nil
	}

	if in.ServiceInstance == nil {
		return nil
	}

	if mutable == nil {
		return nil
	}

	if in.Port.Port != 10443 {
		return nil
	}

	if in.Port.Name != "http2-elements" && in.Port.Name != "https-elements" {
		return nil
	}
	log.Infof("h2sidecar: Manipulating outbound listener for port %v %v bind %v and initial state %v", in.Port, in.Port.Name, in.Bind, mutable)
	setListenerH2S(mutable)
	log.Infof("h2sidecar: %v %v %v mutated state: %v", in.Port, in.Port.Name, in.Bind, mutable)

	return nil
}

// OnInboundListener is called whenever a new listener is added to the LDS output for a given service
// Can be used to add additional filters (e.g., mixer filter) or add more stuff to the HTTP connection manager
// on the inbound path
func (Plugin) OnInboundListener(in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	if in.Node == nil {
		return nil
	}

	if in.Node.Type != model.SidecarProxy {
		return nil
	}

	if in.ListenerCategory == networking.EnvoyFilter_ListenerMatch_SIDECAR_INBOUND {
		return nil
	}

	if in.ServiceInstance == nil {
		return nil
	}

	if mutable == nil {
		return nil
	}

	if in.Port.Port != 10443 {
		return nil
	}

	if in.Port.Name != "http2-elements" && in.Port.Name != "https-elements" {
		return nil
	}
	log.Infof("h2sidecar: Manipulating inbound listener for port %v %v bind %v and initial state %v", in.Port, in.Port.Name, in.Bind, mutable)
	setListenerH2S(mutable)
	log.Infof("h2sidecar: %v %v %v mutated state: %v", in.Port, in.Port.Name, in.Bind, mutable)

	return nil
}

// setListenerH2S configures an listener to talk H2S.
// TLC certs are hardcoded and ALPN is H2 only.
func setListenerH2S(mutable *plugin.MutableObjects) {
	if len(mutable.FilterChains) < 2 {
		log.Info("h2sidecar: Expected at least two listeners in filterchain (mtls and then the default)")
		return
	}

	for ix, filterChain := range mutable.FilterChains {
		log.Infof("h2sidecar: filterchain index %v is %v", ix, filterChain)
	}

	// 0 index is expected to be the mtlschain
	filterChain := mutable.FilterChains[1]
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

	log.Infof("h2sidecar: mutated filterchain to %v", filterChain)
	mutable.FilterChains[1] = filterChain
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

	if in.Port.Port != 10443 {
		return
	}

	if in.Port.Name != "http2-elements" && in.Port.Name != "https-elements" {
		return
	}

	setClusterALPNH2(cluster)
	log.Infof("h2sidecar: Writing elements cluster: %v", cluster)
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
}

// OnInboundRouteConfiguration implements the Plugin interface method.
func (Plugin) OnInboundRouteConfiguration(in *plugin.InputParams, route *xdsapi.RouteConfiguration) {
}

// OnOutboundCluster implements the Plugin interface method.
func (Plugin) OnOutboundCluster(in *plugin.InputParams, cluster *xdsapi.Cluster) {
}

// OnInboundFilterChains is called whenever a plugin needs to setup the filter chains, including relevant filter chain configuration.
func (Plugin) OnInboundFilterChains(in *plugin.InputParams) []plugin.FilterChain {
	return nil
}
