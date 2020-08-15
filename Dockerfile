FROM golang:1.15.0
ENV GOPATH=/go

COPY ./ ./

RUN export GOPATH=`pwd`

CMD go run *.go