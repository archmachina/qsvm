
# test_BUILD_OPTS --build-arg use_image=testing
ARG use_image=base

################
# Base image
FROM python:3.13.5-slim-bullseye AS base

# Work directory
RUN mkdir -p /work/bin && chmod 777 /work
WORKDIR /work
ENV HOME=/work

# Install any OS packages
ARG DEBIAN_FRONTEND=noninteractive
# RUN apt-get update && apt-get install -yq --no-install-recommends sshpass
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Create local user account
RUN groupadd -g 1000 -r user && \
  useradd -u 1000 -g 1000 -d /work user
USER 1000:1000

# Set up python venv
RUN python3 -m venv /work/env && \
    /work/env/bin/pip install --upgrade pip
ENV PATH="/work/env/bin:/work/bin:$PATH"

# Install any python packages
COPY requirements.txt /work/
RUN python3 -m pip install -r /work/requirements.txt && \
    rm -f /work/requirements.txt

COPY entrypoint /work/bin/entrypoint
ENTRYPOINT [ "/work/bin/entrypoint" ]

################
# Testing image
FROM base AS testing

COPY tests /work/tests

COPY tests/entrypoint /work/bin/test-entrypoint
ENTRYPOINT [ "/work/bin/test-entrypoint" ]

COPY tests/requirements.txt /work/test-requirements.txt
RUN python3 -m pip install -r /work/test-requirements.txt && \
    rm -f /work/test-requirements.txt

################
# Final image
FROM ${use_image}

# Copy qsvm module
RUN mkdir /work/modules
ENV PYTHONPATH=/work/modules
COPY qsvm /work/modules/qsvm/

# Save build version
ARG VERSION
RUN echo "${VERSION}" > /work/build_version.txt
RUN echo "$(date --iso-8601=seconds)" > /work/build_date.txt

