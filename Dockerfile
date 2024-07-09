FROM docker:latest

RUN apk update &&  \
    apk upgrade &&  \
    apk add miniupnpc bash

COPY run /opt/portical/

ENV PORTICAL_SPAWN_UPNPC_CONTAINER=true

ENTRYPOINT []
CMD ["/opt/portical/run", "listen"]