#!/bin/bash

SHA=$(git rev-parse HEAD)
OUT_DIR=${1:-../istio-release-$SHA}

mkdir -p "$OUT_DIR"
helm template install/kubernetes/helm/istio --name istio --namespace istio-system --output-dir "$OUT_DIR"
mv "$OUT_DIR"/istio/templates/configmap.yaml "$OUT_DIR"/istio/charts/
cat install/kubernetes/helm/istio-init/files/crd-* > "$OUT_DIR"/istio/charts/crds.yaml
for i in "$OUT_DIR"/istio/charts/*/templates/*.yaml; do mv "$i" "${i//templates/}"; done
for i in "$OUT_DIR"/istio/charts/*/templates; do rmdir "$i"; done
for i in "$OUT_DIR"/istio/charts/*/clusterrolebinding.yaml; do mv "$i" "${i//clusterrolebinding/crb}"; done
for i in "$OUT_DIR"/istio/charts/*/autoscale.yaml; do mv "$i" "${i//autoscale/hpa}"; done
for i in "$OUT_DIR"/istio/charts/*/deployment.yaml; do sed -i 's|gcr.io/istio-release/\(.*\):release-1.2-latest-daily|quay.io/pusher/istio-\1:'"$SHA"'|' "$i"; done
for i in "$OUT_DIR"/istio/charts/*/deployment.yaml; do sed -i 's|IfNotPresent|Always|' "$i"; done
