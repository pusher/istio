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
	for ix, filterChain := range mutable.Listener.FilterChains {
		filterChain.TlsContext = &auth.DownstreamTlsContext{
			CommonTlsContext: &auth.CommonTlsContext{
				TlsCertificates: []*auth.TlsCertificate{
					{CertificateChain: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/certs/tls.crt"}},
						PrivateKey: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/certs/tls.key"}},
					},
				},
				AlpnProtocols: []string{"h2"},
			},
		}
		mutable.Listener.FilterChains[ix] = filterChain
		log.Infof("h2sidecar: OnOutboundListener: At filterchain index %v, writing %v", ix, filterChain)
	}

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

	if in.ListenerCategory != networking.EnvoyFilter_ListenerMatch_SIDECAR_INBOUND {
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

	if in.Port.Name != "https-h2s" && in.Port.Name != "http2-h2s" {
		log.Infof("h2sidecar: OnInboundListener: Port name not http2-h2s or https-h2s . Skipping %v %v", in, mutable)
		return nil
	}

	log.Infof("h2sidecar: OnInboundListener: Mutating %v %v", in, mutable)

	// TODO: Restrict port name?
	for ix, filterChain := range mutable.Listener.FilterChains {
		// TODO: Why are we skipping 0? Encode the filter we're trying to modify better.
		if ix == 0 {
			continue
		}

		filterChain.TlsContext = &auth.DownstreamTlsContext{
			CommonTlsContext: &auth.CommonTlsContext{
				// TODO: Is this requiring mutual TLS?
				TlsCertificates: []*auth.TlsCertificate{
					{CertificateChain: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/certs/tls.crt"}},
						PrivateKey: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/certs/tls.key"}},
					},
				},
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
		}
		mutable.Listener.FilterChains[ix] = filterChain
		log.Infof("h2sidecar: OnInboundListener: At filterchain index %v, writing %v", ix, filterChain)
	}

	return nil
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

	if in.Port.Name != "http2" && in.Port.Name != "http2-h2s" {
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
