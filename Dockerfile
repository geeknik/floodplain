#
# Floodplain Dockerfile
#
# https://github.com/geeknik/floodplain
#
# Written by: Michael Pellon <m@pellon.io>
# Updated by: Chandrapal <bnchandrapal@protonmail.com>
# Updated by: Steve Micallef <steve@binarypool.com>
# Updated by: Steve Bate <svc-spiderfoot@stevebate.net>
#    -> Inspired by https://github.com/combro2k/dockerfiles/tree/master/alpine-spiderfoot
#
# Usage:
#
#   sudo docker build -t floodplain .
#   sudo docker run -p 5001:5001 --security-opt no-new-privileges floodplain
#
# Using Docker volume for floodplain data
#
#   sudo docker run -p 5001:5001 -v /mydir/floodplain:/var/lib/floodplain floodplain
#
# Using Floodplain remote command line with web server
#
#   docker run --rm -it floodplain sfcli.py -s http://my.floodplain.host:5001/
#
# Running floodplain commands without web server (can optionally specify volume)
#
#   sudo docker run --rm floodplain sf.py -h
#
# Running a shell in the container for maintenance
#   sudo docker run -it --entrypoint /bin/sh floodplain
#
# Running floodplain unit tests in container
#
#   sudo docker build -t floodplain-test --build-arg REQUIREMENTS=test/requirements.txt .
#   sudo docker run --rm floodplain-test -m pytest --flake8 .

FROM alpine:3.12.4 AS build
ARG REQUIREMENTS=requirements.txt
RUN apk add --no-cache gcc git curl python3 python3-dev py3-pip swig tinyxml-dev \
 python3-dev musl-dev openssl-dev libffi-dev libxslt-dev libxml2-dev jpeg-dev \
 openjpeg-dev zlib-dev cargo rust
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin":$PATH
COPY $REQUIREMENTS requirements.txt ./
RUN ls
RUN echo "$REQUIREMENTS"
RUN pip3 install -U pip
RUN pip3 install -r "$REQUIREMENTS"



FROM alpine:3.13.0
WORKDIR /home/floodplain

# Place database and logs outside installation directory
ENV FLOODPLAIN_DATA /var/lib/floodplain
ENV FLOODPLAIN_LOGS /var/lib/floodplain/log
ENV FLOODPLAIN_CACHE /var/lib/floodplain/cache

# Run everything as one command so that only one layer is created
RUN apk --update --no-cache add python3 musl openssl libxslt tinyxml libxml2 jpeg zlib openjpeg \
    && addgroup floodplain \
    && adduser -G floodplain -h /home/floodplain -s /sbin/nologin \
               -g "Floodplain User" -D floodplain \
    && rm -rf /var/cache/apk/* \
    && rm -rf /lib/apk/db \
    && rm -rf /root/.cache \
    && mkdir -p $FLOODPLAIN_DATA || true \
    && mkdir -p $FLOODPLAIN_LOGS || true \
    && mkdir -p $FLOODPLAIN_CACHE || true \
    && chown floodplain:floodplain $FLOODPLAIN_DATA \
    && chown floodplain:floodplain $FLOODPLAIN_LOGS \
    && chown floodplain:floodplain $FLOODPLAIN_CACHE

COPY . .
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

USER floodplain

EXPOSE 5001

# Run the application.
ENTRYPOINT ["/opt/venv/bin/python"]
CMD ["sf.py", "-l", "0.0.0.0:5001"]
