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
#   sudo docker run --rm floodplain-test -m pytest test/unit
#
# Python 3.11+ is required. Both stages use the same official Python image so
# the virtualenv built in the first stage runs unchanged in the second.

FROM python:3.13-alpine3.24@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca AS build
ARG REQUIREMENTS=requirements.txt
# Alpine packages track the digest-pinned base; exact apk pins break rebuilds.
# hadolint ignore=DL3018
RUN apk add --no-cache gcc musl-dev swig tinyxml-dev openssl-dev libffi-dev \
 libxslt-dev libxml2-dev jpeg-dev openjpeg-dev zlib-dev cargo rust
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
COPY requirements.txt requirements.lock ./
COPY test/requirements.txt test/requirements.txt
# Runtime dependencies are installed hash-verified from the lockfile.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
# Optional extras (e.g. test tooling) on top of the locked runtime set.
RUN if [ "$REQUIREMENTS" != "requirements.txt" ]; then pip install --no-cache-dir -r "$REQUIREMENTS"; fi


FROM python:3.13-alpine3.24@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca
WORKDIR /home/floodplain

# Place database and logs outside installation directory
ENV FLOODPLAIN_DATA /var/lib/floodplain
ENV FLOODPLAIN_LOGS /var/lib/floodplain/log
ENV FLOODPLAIN_CACHE /var/lib/floodplain/cache

# Run everything as one command so that only one layer is created
# hadolint ignore=DL3018
RUN apk --update --no-cache add libxslt tinyxml libxml2 jpeg zlib openjpeg \
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

# hadolint ignore=DL3066
USER floodplain

EXPOSE 5001

# Run the application.
ENTRYPOINT ["/opt/venv/bin/python"]
CMD ["sf.py", "-l", "0.0.0.0:5001"]
