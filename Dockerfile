# Cross-compile rather than emulate.
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /hush-exporter ./cmd/hush-exporter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /hush-exporter /hush-exporter
EXPOSE 10057
ENTRYPOINT ["/hush-exporter"]
