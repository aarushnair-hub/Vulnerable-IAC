# ============================================================================
#  docker/Dockerfile  —  INTENTIONALLY INSECURE DOCKERFILE
#  DO NOT BUILD/SHIP.  Test fixture for Checkov (dockerfile) / OX scanning.
#  Trips: CKV_DOCKER_* (root user, latest tag, ADD, curl|sh, secrets, ...)
# ============================================================================

# Unpinned 'latest' base image  (CKV_DOCKER_7)
FROM ubuntu:latest

# Hardcoded secret in ENV  (secrets framework / CKV_DOCKER_*)
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV API_TOKEN=supersecrettoken123

# Remote ADD instead of COPY  (CKV_DOCKER_4)
ADD https://example.com/installer.sh /tmp/installer.sh

# Pipe-to-shell install, update without cleanup, no version pinning
RUN apt-get update && \
    apt-get install -y sudo curl && \
    curl -fsSL https://example.com/setup.sh | sh

# Exposing SSH / running an admin daemon
EXPOSE 22

# No USER directive -> container runs as root  (CKV_DOCKER_3)
# No HEALTHCHECK                                (CKV_DOCKER_2)

CMD ["bash"]
