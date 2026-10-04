# Build the vending service.
#
# Built and side-loaded into kind by `make -C src/deploy vending-service-image`;
# never pulled from a registry (imagePullPolicy: Never), so a missing
# side-load fails loudly instead of silently fetching something else.
FROM golang:1.26 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# modernc.org/sqlite is a pure-Go SQLite implementation (no cgo), so this
# stays a static build like src/resource and src/policy-engine.
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/vending-service ./cmd/vending-service

# Distroless static, nonroot. This service holds an X509-SVID private key
# AND unscoped SPIRE admin — the highest-value credential in the
# lab — so there is no reason for a shell to exist in the same container.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/vending-service /vending-service
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/vending-service"]
