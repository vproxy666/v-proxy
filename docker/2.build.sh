#!/bin/bash

#https://medium.com/@artur.klauser/building-multi-architecture-docker-images-with-buildx-27d80f7e2408
# sudo apt-get install qemu binfmt-support qemu-user-static



line="$(grep -oP '(?:pub\s+static\s+VERSION\s*\:\s*\&str\s*\=\s*\")[0-9]+\.[0-9]+\.[0-9]+'  ../src/main.rs)"
IMAGE_VERSION=${line##*\"}
IMAGE_URI=vproxy/server:v${IMAGE_VERSION}
echo $IMAGE_URI

#sudo docker build -t="vproxy/server:latest" .
#sudo docker push "vproxy/server:$version"
#sudo docker push vproxy/server:latest

# Normalize ARCH name in tag so that we can build multi-arch images
CERTBOT_VERSION=v1.8.0

docker pull certbot/certbot:amd64-$CERTBOT_VERSION
docker image tag certbot/certbot:amd64-$CERTBOT_VERSION vproxy/certbot:amd64-$CERTBOT_VERSION
docker push vproxy/certbot:amd64-$CERTBOT_VERSION

docker pull certbot/certbot:arm64v8-$CERTBOT_VERSION
docker image tag certbot/certbot:arm64v8-$CERTBOT_VERSION vproxy/certbot:arm64-$CERTBOT_VERSION
docker push vproxy/certbot:arm64-$CERTBOT_VERSION

docker pull certbot/certbot:arm32v6-$CERTBOT_VERSION
docker image tag certbot/certbot:arm32v6-$CERTBOT_VERSION vproxy/certbot:arm-$CERTBOT_VERSION
docker push vproxy/certbot:arm-$CERTBOT_VERSION




export DOCKER_CLI_EXPERIMENTAL=enabled
docker buildx build -t $IMAGE_URI --platform linux/amd64,linux/arm/v7,linux/arm64/v8 --push .


# if you see error "auto-push is currently not implemented for docker driver"
# Run : docker buildx create --use


docker image tag $IMAGE_URI vproxy/server:latest
docker push vproxy/server:latest
