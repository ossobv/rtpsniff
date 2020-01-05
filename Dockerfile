FROM debian:jessie

ARG version=1.0-1

RUN apt-get update && apt-get install -qy build-essential dh-make libpcap-dev dh-systemd
ADD . /rtpsniff
WORKDIR /rtpsniff
RUN dpkg-buildpackage -uc -us -b
CMD cp ../rtpsniff_${version}_amd64.deb .

ENV version=$version

CMD echo && mkdir /build/rtpsniff_${version} && \
    mv /rtpsniff_${version}_amd64.deb /build/rtpsniff_${version}/ && \
    chown -R ${UID}:root  /build/rtpsniff_${version} && \
    cd /build && find . -type f && echo && echo 'Output files created succesfully'
