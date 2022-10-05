FROM debian:buster

RUN apt-get update && apt-get -y install \
	build-essential \
	gcc \
	cmake \
	git \
	libpthread-stubs0-dev \
	libevent-2.1-6 \
	libevent-dev \
	libevent-openssl-2.1-6 \
	libssl-dev \
	libev4 \
	libev-dev \
	libc-ares2 \
	libc-ares-dev \
	zlib1g \
	zlib1g-dev \
	libboost-system1.67 \
	libboost-thread1.67 \
	libboost-log1.67 \
	libboost-chrono1.67 \
	libboost-date-time1.67 \
	libboost-atomic1.67 \
	libboost-filesystem1.67 \
	libboost-regex1.67

RUN apt-get -y install --reinstall ca-certificates

WORKDIR /app

ARG STEP_CLONE_NGHTTP2=true
RUN git clone https://github.com/ipint-axxonsoft/nghttp2.git \
	&& git -C nghttp2 checkout --track origin/onvif_uplink

RUN git clone https://github.com/ipint-axxonsoft/websocket_cpp.git

RUN cp -R websocket_cpp/include/websocket_cpp nghttp2/src/includes/

RUN cmake ./nghttp2 -Bbuild -DENABLE_ASIO_LIB=1 -DENABLE_EXAMPLES=1

RUN	cd build && make