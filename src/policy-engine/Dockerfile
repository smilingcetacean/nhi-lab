# Build the policy engine.
#
# Built and side-loaded into kind by `make -C src/deploy policy-engine-image`;
# never pulled from a registry. The Deployment sets imagePullPolicy: Never so
# a missing side-load fails loudly instead of silently fetching something
# else.
FROM golang:1.26 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/policy-engine .

# Distroless static, nonroot. This service holds an X509-SVID private key in
# memory and is the only identity in the cluster allowed to write Rego to
# OPA; there is no reason for a shell to exist in the same container.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/policy-engine /policy-engine
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/policy-engine"]
