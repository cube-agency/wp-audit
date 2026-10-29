FROM php:8.4-cli-alpine
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates

COPY wp-audit.php /opt/wp-audit/
RUN printf '#!/bin/sh\nexec php /opt/wp-audit/wp-audit.php "$@"\n' > /usr/local/bin/wp-audit \
    && chmod +x /usr/local/bin/wp-audit \
    && php -l /opt/wp-audit/wp-audit.php

WORKDIR /work
CMD ["wp-audit"]
