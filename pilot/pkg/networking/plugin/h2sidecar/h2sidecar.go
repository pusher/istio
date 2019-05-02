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
	"fmt"
	"strconv"

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

// Terminate TLS at the outbound listener.
//
// You may want this if:
// - You have existing workloads that require TLS
//   - Perhaps TLS cannot be disabled. For example Go cannot easily talk http2 without TLS.
// - You do not wish to passthrough the TLS to the destination workload.
//   - Because you need to inspect the underlying data for routing
//   - Or you wish to balance individual h2 streams across destination endpoints
//
// The downsides of this approach are:
// - All destinations listening on the same port will be required to talk TLS
//   as the listener will capture traffic to each of them.
// - A valid certificate needs to be provided which the workload must recognise
//   as belonging to every destination.
//   I.E. either:
//   - Each destination must use the same certificate and it must be mounted locally.
//   - A dummy certificate must be used and communication from workload to the
//     sidecar cannot verify ownership of the cert.
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

	// If there is no annotated port, or the annotation is empty, there is nothing to do.
	h2sidecarPorts, err := getListenerPorts(in)
	if err != nil {
		return err
	}
	if h2sidecarPorts == nil {
		return nil
	}

	// If the port we're building a listener for does not match a provided port,
	// there is nothing to do.
	match := false
	for _, matchPort := range h2sidecarPorts {
		match = match || in.Port.Port == matchPort
	}
	if !match {
		return nil
	}

	outboundCertificate := getCertificate(in)
	if outboundCertificate == nil {
		// TODO: Is defining no/ empty paths an error?
		return nil
	}

	for ix, filterChain := range mutable.Listener.FilterChains {
		// TODO:
		// - Should every filterchain be modified?
		// - Insert rather than modify?
		// - ALPN could contain more than h2
		filterChain.TlsContext = &auth.DownstreamTlsContext{
			CommonTlsContext: &auth.CommonTlsContext{
				TlsCertificates: []*auth.TlsCertificate{outboundCertificate},
				AlpnProtocols:   []string{"h2"},
			},
		}
		mutable.Listener.FilterChains[ix] = filterChain
		log.Infof("h2sidecar: OnOutboundListener: At filterchain index %v, writing %v", ix, filterChain)
	}

	return nil
}

// read the port whose listener should have TLS settings added.
// TODO:
// - Parse string as possible list of ports.
// - Ports could be defined on sidecar/ destinationrule CRD rather than annotation.
// - Inbound ports could also be configured by port name suffix.
func getListenerPorts(in *plugin.InputParams) ([]int, error) {
	if in.Node == nil {
		return nil, nil
	}

	var direction string
	switch in.ListenerCategory {
	case networking.EnvoyFilter_ListenerMatch_SIDECAR_OUTBOUND:
		direction = "outbound"
	case networking.EnvoyFilter_ListenerMatch_SIDECAR_INBOUND:
		direction = "inbound"
	case networking.EnvoyFilter_ListenerMatch_GATEWAY:
		direction = "gateway"
	default:
		return nil, nil
	}

	h2sidecarPortStr, ok := in.Node.Metadata[fmt.Sprintf("istio.io/h2sidecar-%v-port", direction)]
	if !ok {
		return nil, nil
	}

	h2sidecarPort, err := strconv.Atoi(h2sidecarPortStr)
	if err != nil {
		return nil, err
	}

	return []int{h2sidecarPort}, nil
}

// read paths to TLS certificates for a listener.
// The certificate chain and private key may not be set.
// TODO:
// - Outbound certs can be configured on sidecar crd
// - Inbound certs could/ should be configured by the corresponding destinationrule?
//   For the time being the annotation should probably point to the same cert.
func getCertificate(in *plugin.InputParams) *auth.TlsCertificate {
	if in.Node == nil {
		return nil
	}

	var direction string
	switch in.ListenerCategory {
	case networking.EnvoyFilter_ListenerMatch_SIDECAR_OUTBOUND:
		direction = "outbound"
	case networking.EnvoyFilter_ListenerMatch_SIDECAR_INBOUND:
		direction = "inbound"
	case networking.EnvoyFilter_ListenerMatch_GATEWAY:
		direction = "gateway"
	default:
		return nil
	}

	cert := &auth.TlsCertificate{}

	chain, ok := in.Node.Metadata[fmt.Sprintf("istio.io/h2sidecar-%v-certificateChain", direction)]
	if ok {
		cert.CertificateChain = &core.DataSource{
			Specifier: &core.DataSource_Filename{
				Filename: chain,
			}}
	}

	privateKey, ok := in.Node.Metadata[fmt.Sprintf("istio.io/h2sidecar-%v-privateKey", direction)]
	if ok {
		cert.PrivateKey = &core.DataSource{
			Specifier: &core.DataSource_Filename{
				Filename: privateKey,
			}}
	}

	return cert
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

	// If there is no annotated port, or the annotation is empty, there is nothing to do.
	h2sidecarPorts, err := getListenerPorts(in)
	if err != nil {
		return err
	}
	if h2sidecarPorts == nil {
		return nil
	}

	// If the port we're building a listener for does not match a provided port,
	// there is nothing to do.
	match := false
	for _, matchPort := range h2sidecarPorts {
		match = match || in.Port.Port == matchPort
	}
	if !match {
		return nil
	}

	inboundCertificate := getCertificate(in)
	if inboundCertificate == nil {
		// TODO: Is defining no/ empty paths an error?
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
				TlsCertificates: []*auth.TlsCertificate{inboundCertificate},
				AlpnProtocols:   []string{"h2", "http/1.1"},
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
