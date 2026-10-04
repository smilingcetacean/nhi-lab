# Build the protected resource.
#
# Built and side-loaded into kind by `make -C src/deploy resource-image`; never
# pulled from a registry. The Deployment sets imagePullPolicy: Never so a
# missing side-load fails loudly instead of silently fetching something else.
FROM golang:1.26 AS build

WORKDIR /src
# Copy the module files first so dependency download is cached independently of
# source edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO off and a static build: the runtime stage has no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/resource .

# Distroless static, nonroot. The resource holds an X509-SVID private key in
# memory; there is no reason for a shell to exist in the same container.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/resource /resource
# 65532 is distroless's `nonroot`. The Workload API socket is world-writable on
# the node, so an unprivileged UID still reaches it.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/resource"]
