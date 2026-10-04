# Agent harness image: both parent.py and child.py ship in the same
# image (like cmd/parentsim plays both parent and child roles in
# verify-vending.sh), dispatched by the k8s manifest's `command`.
#
# python:3.13-slim, not distroless: unlike the vending service (Go, static
# binary, under the "nothing should be able to pull the identity holding
# unscoped SPIRE admin" rationale for a minimal image), this is an ordinary
# Python workload with a real dependency set (spiffe, kubernetes client,
# cryptography) that need a working libc/OpenSSL, and it holds no
# equivalent unscoped privilege — its only elevated capability is the k8s
# RBAC grant to create pods in one namespace (manifests/agents/), scoped by
# a Role, not a ClusterRole.
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common.py manifest.py parent.py child.py ./

# No ENTRYPOINT/CMD: the k8s manifests set `command` explicitly
# (["python3", "/app/parent.py"] or ["python3", "/app/child.py"]) — same
# "one image, dispatch by command" shape cmd/parentsim's manifests use.
