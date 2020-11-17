FROM vproxy/certbot:${TARGETARCH}-v1.8.0

ENV USER=app_user
ENV UID=33333
ENV GID=44444

RUN apk add libcap && mkdir /app && mkdir /app/data && \
    addgroup --gid "$GID" "$USER" \
    && adduser \
    --disabled-password \
    --gecos "" \
    --home "/app" \
    --ingroup "$USER" \
    --no-create-home \
    --uid "$UID" \
    "$USER"



EXPOSE 80/tcp 443/tcp

 
ENV RUST_BACKTRACE=1
ENV RUST_LOG=info


WORKDIR /app
ARG TARGETPLATFORM
ADD bin/${TARGETPLATFORM}/v-proxy /app/
VOLUME ["/app/data"]
COPY web /app/web

# Allow non-root user to bind on port lower than 1024
RUN setcap CAP_NET_BIND_SERVICE=+eip /app/v-proxy  
#USER app_user  # certbot image requires permissions

ENTRYPOINT [ "/app/v-proxy" ]
CMD ["--http_port", "80", "--https_port", "443"]
