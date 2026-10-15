ARG GO_VERSION=1.27.2
FROM golang:${GO_VERSION} AS build

WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

FROM scratch AS client
COPY --from=build /out/client /client
COPY testdata/input.json /data/input.json
USER 65534:65534
ENTRYPOINT ["/client"]
CMD ["-file", "/data/input.json", "-server", "http://server:8080"]

FROM scratch AS server
COPY --from=build /out/server /server
COPY rules/rules.json /rules/rules.json
USER 65534:65534
ENV RULES_PATH=/rules/rules.json
ENV ADDR=:8080
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=12 \
    CMD ["/server", "health"]
ENTRYPOINT ["/server"]
