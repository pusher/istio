#!/bin/bash

SHA=$(git rev-parse HEAD)

helm template install/kubernetes/helm/istio --name istio --namespace istio-system --output-dir ../istio-release-1.1/
mv ../istio-release-1.1/istio/templates/configmap.yaml ../istio-release-1.1/istio/charts/
cat install/kubernetes/helm/istio-init/files/crd-* > ../istio-release-1.1/istio/charts/crds.yaml
for i in ../istio-release-1.1/istio/charts/*/templates/*.yaml; do mv $i $(echo $i | sed -e 's|templates/||g'); done
for i in ../istio-release-1.1/istio/charts/*/templates; do rmdir $i; done
for i in ../istio-release-1.1/istio/charts/*/clusterrolebindings.yaml; do mv $i $(echo $i | sed -e 's|clusterrolebindings|crb|g'); done
for i in ../istio-release-1.1/istio/charts/*/clusterrolebinding.yaml; do mv $i $(echo $i | sed -e 's|clusterrolebinding|crb|g'); done
for i in ../istio-release-1.1/istio/charts/*/autoscale.yaml; do mv $i $(echo $i | sed -e 's|autoscale|hpa|g'); done
for i in ../istio-release-1.1/istio/charts/*/deployment.yaml; do sed -i 's|gcr.io/istio-release/\(.*\):release-1.1-latest-daily|quay.io/pusher/istio-\1:'$SHA'|' $i; done
for i in ../istio-release-1.1/istio/charts/*/deployment.yaml; do sed -i 's|IfNotPresent|Always|' $i; done
