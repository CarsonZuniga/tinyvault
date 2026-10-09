FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tinyvault ./cmd/tinyvault

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /tinyvault /tinyvault
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/tinyvault"]
CMD ["serve"]
