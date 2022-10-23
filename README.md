# onvif_uplink_applications
Onvif Uplink

### Getting started

Download, install and setup Docker.

Build this project using command `docker build --pull --rm -f "Dockerfile" -t onvifuplinkapplications:latest "."`

To run applications we recommend next way:

If you want to run cloud application use command:
1. `docker run --rm -it -p <listen http2 port>:<listen http2 port> -p <listen http port>:<listen http port> -p <listen rtsp port>:<listen rtsp port> onvifuplinkapplications:latest`

2. `./build/examples/uplink_cloud_service (--http2-tls-port=<port> | --http2-port=<port>) [--http-port=<port>] [--rtsp-port=<port>]`

If you want to run camera application use command:
1. `docker run --rm -it onvifuplinkapplications:latest`

2. `./build/examples/uplink_camera_service --cloud-ip=<ip> --http2-port=<port> --camera-ip=<ip> [--camera-http-port=<port>] [--camera-rtsp-port=<port>]`

Examples:

```
docker run --rm -it -p 8090:8090 -p 8080:8080 -p 8554:8554 onvifuplinkapplications:latest
./build/examples/uplink_cloud_service --http2-tls-port=8090  --http-port=8080 --rtsp-port=8554
```

NOTE: Please make sure you are in the working directory "/app" and running all commands from there. It's important because some recourse files may be located there and applications may load them.