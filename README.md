# onvif_uplink_applications
Onvif Uplink

### Getting started

Download, install and setup Docker.

Build this project using command `docker build --pull --rm -f "Dockerfile" -t onvifuplinkapplications:latest "."`

To run applications we recommend next way:

If you want to run cloud application use command:
1. `docker run --rm -it -p <listen http2 port>:<listen http2 port> -p <listen http port>:<listen http port> -p <listen rtsp port>:<listen rtsp port> onvifuplinkapplications:latest`

2. `./build/examples/uplink_cloud_service <listen http2 port> <listen http port> <listen rtsp port>`

If you want to run camera application use command:
1. `docker run --rm -it onvifuplinkapplications:latest`

2. `./build/examples/uplink_camera_service <cloud server ip address> <cloud server http2 port> <camera ip> <camera http port> <camera rtsp port>`

Examples:

```
docker run --rm -it -p 8090:8090 -p 8080:8080 -p 8554:8554 onvifuplinkapplications:latest
./build/examples/uplink_cloud_service 8090 8080 8554
```