FROM alpine:3.7

WORKDIR /project

COPY . /project/pcpy

RUN apk update \
  && apk add make \
  && apk add g++ \
  && rm -rf /var/cache/apk/*

RUN apk add libpcap-dev \
  && cd /project/pcpy/pcpy \
  && make main

CMD ["/project/pcpy/pcpy/main"]
