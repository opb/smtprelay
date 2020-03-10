FROM golang:1.14-alpine as build-env
WORKDIR /build
ADD go.* ./
RUN go mod download
ADD . ./
RUN CGO_ENABLED=0 go build -o smtprelay

FROM alpine:3.11
WORKDIR /app
RUN apk add --no-cache ca-certificates && rm -rf /var/cache/apk/*
COPY --from=build-env /build/smtprelay /app
CMD ["/app/smtprelay"]
