#!/bin/bash
set -e

CLUSTER_NAME=bridgekeeper-test
DOCKER_IMAGE=bridgekeeper
DOCKER_TAG=test
DOCKER_VERSION=$DOCKER_IMAGE:$DOCKER_TAG

k3d cluster create $CLUSTER_NAME

k3d kubeconfig get $CLUSTER_NAME > kubeconfig
export KUBECONFIG=$(pwd)/kubeconfig

cd ..
# Build docker image
docker build . -t $DOCKER_VERSION
k3d image import -c $CLUSTER_NAME $DOCKER_VERSION
# Deploy helm chart with built docker image
helm install --namespace bridgekeeper --create-namespace bridgekeeper ./charts/bridgekeeper --set image.repository=$DOCKER_IMAGE --set image.tag=$DOCKER_TAG --wait

cd functional_tests
python execute_tests.py

k3d cluster delete $CLUSTER_NAME
