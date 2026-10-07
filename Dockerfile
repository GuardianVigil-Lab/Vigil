# syntax=docker/dockerfile:1
# Vigil — Unified Enterprise QA, Security, VAPT & Review Engine
# Multi-stage build on debian:bookworm-slim

# ==============================================================================
# Stage 1: Binary Extractor
# ==============================================================================
FROM debian:bookworm-slim AS extractor

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    unzip \
    tar \
    gzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /out/bin

RUN case "${TARGETARCH}" in \
      arm64) \
        HADOLINT_ARCH="arm64"; \
        ZIZMOR_ARCH="aarch64-unknown-linux-gnu"; \
        GITLEAKS_ARCH="linux_arm64"; \
        TRUFFLEHOG_ARCH="linux_arm64"; \
        SYFT_ARCH="linux_arm64"; \
        GRYPE_ARCH="linux_arm64"; \
        TRIVY_ARCH="Linux-ARM64"; \
        SG_ARCH="aarch64-unknown-linux-gnu"; \
        SQUAWK_ARCH="linux-arm64"; \
        NUCLEI_ARCH="linux_arm64"; \
        FFUF_ARCH="linux_arm64"; \
        OASDIFF_ARCH="linux_arm64"; \
        DOCKLE_ARCH="Linux-ARM64"; \
        TOXIPROXY_ARCH="linux-arm64"; \
        STRIX_ARCH="arm64"; \
        REVIEWDOG_ARCH="Linux_arm64" ;; \
      *) \
        HADOLINT_ARCH="x86_64"; \
        ZIZMOR_ARCH="x86_64-unknown-linux-gnu"; \
        GITLEAKS_ARCH="linux_x64"; \
        TRUFFLEHOG_ARCH="linux_amd64"; \
        SYFT_ARCH="linux_amd64"; \
        GRYPE_ARCH="linux_amd64"; \
        TRIVY_ARCH="Linux-64bit"; \
        SG_ARCH="x86_64-unknown-linux-gnu"; \
        SQUAWK_ARCH="linux-x86_64"; \
        NUCLEI_ARCH="linux_amd64"; \
        FFUF_ARCH="linux_amd64"; \
        OASDIFF_ARCH="linux_amd64"; \
        DOCKLE_ARCH="Linux-64bit"; \
        TOXIPROXY_ARCH="linux-amd64"; \
        STRIX_ARCH="x86_64"; \
        REVIEWDOG_ARCH="Linux_x86_64" ;; \
    esac && \
    curl -fsSL https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-${HADOLINT_ARCH} -o hadolint && chmod +x hadolint && \
    curl -fsSL https://github.com/woodruffw/zizmor/releases/download/v1.30.1/zizmor-${ZIZMOR_ARCH}.tar.gz | tar -xz -C /out/bin zizmor && chmod +x zizmor && \
    curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.24.0/gitleaks_8.24.0_${GITLEAKS_ARCH}.tar.gz | tar -xz -C /out/bin gitleaks && chmod +x gitleaks && \
    curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.98.1/trufflehog_3.98.1_${TRUFFLEHOG_ARCH}.tar.gz | tar -xz -C /out/bin trufflehog && chmod +x trufflehog && \
    curl -fsSL https://github.com/anchore/syft/releases/download/v1.20.0/syft_1.20.0_${SYFT_ARCH}.tar.gz | tar -xz -C /out/bin syft && chmod +x syft && \
    curl -fsSL https://github.com/anchore/grype/releases/download/v0.88.0/grype_0.88.0_${GRYPE_ARCH}.tar.gz | tar -xz -C /out/bin grype && chmod +x grype && \
    curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_${TRIVY_ARCH}.tar.gz | tar -xz -C /out/bin trivy && chmod +x trivy && \
    curl -fsSL https://github.com/ast-grep/ast-grep/releases/download/0.45.3/app-${SG_ARCH}.zip -o /tmp/sg.zip && unzip -q -o /tmp/sg.zip -d /out/bin && chmod +x /out/bin/ast-grep /out/bin/sg && rm -f /tmp/sg.zip && \
    curl -fsSL https://github.com/sbdchd/squawk/releases/download/v0.25.0/squawk-${SQUAWK_ARCH} -o squawk && chmod +x squawk && \
    curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_${NUCLEI_ARCH}.zip -o /tmp/nuclei.zip && unzip -q -o /tmp/nuclei.zip nuclei -d /out/bin && chmod +x nuclei && rm -f /tmp/nuclei.zip && \
    curl -fsSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_${FFUF_ARCH}.tar.gz | tar -xz -C /out/bin ffuf && chmod +x ffuf && \
    curl -fsSL https://github.com/oasdiff/oasdiff/releases/download/v1.33.0/oasdiff_1.33.0_${OASDIFF_ARCH}.tar.gz | tar -xz -C /out/bin oasdiff && chmod +x oasdiff && \
    curl -fsSL https://github.com/goodwithtech/dockle/releases/download/v0.4.14/dockle_0.4.14_${DOCKLE_ARCH}.tar.gz | tar -xz -C /out/bin dockle && chmod +x dockle && \
    curl -fsSL https://github.com/Shopify/toxiproxy/releases/download/v2.12.0/toxiproxy-cli-${TOXIPROXY_ARCH} -o toxiproxy-cli && chmod +x toxiproxy-cli && \
    curl -fsSL https://github.com/Shopify/toxiproxy/releases/download/v2.12.0/toxiproxy-server-${TOXIPROXY_ARCH} -o toxiproxy-server && chmod +x toxiproxy-server && \
    curl -fsSL https://github.com/usestrix/strix/releases/download/v1.7.0/strix-1.7.0-linux-${STRIX_ARCH}.tar.gz | tar -xz -C /tmp && mv /tmp/strix-1.7.0-linux-${STRIX_ARCH} /out/bin/strix && chmod +x /out/bin/strix && \
    curl -fsSL https://github.com/reviewdog/reviewdog/releases/download/v0.20.3/reviewdog_0.20.3_${REVIEWDOG_ARCH}.tar.gz | tar -xz -C /out/bin reviewdog && chmod +x /out/bin/reviewdog

# 17. testssl.sh (v3.0.8)
RUN mkdir -p /out/testssl && \
    curl -fsSL https://github.com/testssl/testssl.sh/archive/refs/tags/v3.0.8.tar.gz | tar -xz --strip-components=1 -C /out/testssl

# 18. nikto (v2.5.0)
RUN mkdir -p /out/nikto && \
    curl -fsSL https://github.com/sullo/nikto/archive/refs/tags/2.5.0.tar.gz | tar -xz --strip-components=1 -C /out/nikto

# 19. PHARs (phpstan, psalm, phpcs)
WORKDIR /out/phars
RUN curl -fsSL https://github.com/phpstan/phpstan/releases/latest/download/phpstan.phar -o phpstan.phar && \
    curl -fsSL https://github.com/vimeo/psalm/releases/latest/download/psalm.phar -o psalm.phar && \
    curl -fsSL https://squizlabs.github.io/PHP_CodeSniffer/phpcs.phar -o phpcs.phar


# ==============================================================================
# Stage 2: Runtime Environment
# ==============================================================================
FROM debian:bookworm-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TARGETARCH=amd64

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Base runtime packages + Chromium + nmap + perl
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    gosu \
    libatomic1 \
    libmagic1 \
    unzip \
    tar \
    gzip \
    docker.io \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    php8.2-cli \
    php8.2-curl \
    php8.2-mbstring \
    php8.2-xml \
    nmap \
    perl \
    chromium \
    bsdextrautils \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 26.x and Go 1.27.1 for target architecture
RUN case "${TARGETARCH}" in \
      arm64) NODE_ARCH="arm64"; GO_ARCH="arm64" ;; \
      *)     NODE_ARCH="x64";   GO_ARCH="amd64" ;; \
    esac && \
    curl -fsSL https://nodejs.org/dist/latest-v26.x/node-v26.10.0-linux-${NODE_ARCH}.tar.gz | tar -xz --strip-components=1 -C /usr/local && \
    curl -fsSL https://go.dev/dl/go1.27.1.linux-${GO_ARCH}.tar.gz | tar -xz -C /usr/local
ENV PATH="/usr/local/go/bin:/go/bin:/usr/local/bin:$PATH"
ENV GOPATH="/go"

# Copy pre-compiled binaries, PHARs, testssl, nikto from extractor
COPY --from=extractor /out/bin/* /usr/local/bin/
RUN mkdir -p /usr/local/share/php /usr/local/share/testssl /usr/local/share/nikto
COPY --from=extractor /out/phars/* /usr/local/share/php/
COPY --from=extractor /out/testssl /usr/local/share/testssl/
COPY --from=extractor /out/nikto /usr/local/share/nikto/

# Create execution wrappers
RUN printf '#!/bin/sh\nexec php /usr/local/share/php/phpstan.phar "$@"\n' > /usr/local/bin/phpstan && chmod +x /usr/local/bin/phpstan && \
    printf '#!/bin/sh\nexec php /usr/local/share/php/psalm.phar "$@"\n' > /usr/local/bin/psalm && chmod +x /usr/local/bin/psalm && \
    printf '#!/bin/sh\nexec php /usr/local/share/php/phpcs.phar "$@"\n' > /usr/local/bin/phpcs && chmod +x /usr/local/bin/phpcs && \
    ln -sf /usr/local/share/testssl/testssl.sh /usr/local/bin/testssl.sh && chmod +x /usr/local/bin/testssl.sh && \
    printf '#!/bin/sh\nexec perl /usr/local/share/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto && chmod +x /usr/local/bin/nikto && \
    ln -sf /usr/local/bin/ast-grep /usr/local/bin/sg

# Configure Playwright to use system chromium without downloading extra binaries
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# Install npm globals
RUN npm install -g --no-audit --no-fund \
    knip@5 \
    dependency-cruiser@16 \
    @stryker-mutator/core@8 \
    @stryker-mutator/vitest-runner@8 \
    oxlint \
    fast-check \
    tsx \
    jscpd@4 \
    playwright@1.48.2

# Set up Playwright binary directory and permissions
RUN mkdir -p /ms-playwright && \
    chmod -R 777 /ms-playwright

# Install Go analysis tools
RUN GOBIN=/usr/local/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.5 && \
    GOBIN=/usr/local/bin go install golang.org/x/vuln/cmd/govulncheck@latest && \
    GOBIN=/usr/local/bin go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    GOBIN=/usr/local/bin go install golang.org/x/tools/cmd/deadcode@latest && \
    GOBIN=/usr/local/bin go install go.uber.org/nilaway/cmd/nilaway@latest && \
    GOBIN=/usr/local/bin go install github.com/zimmski/go-mutesting/cmd/go-mutesting@latest && \
    rm -rf /root/.cache/go-build /go/pkg

# Install Python tools
RUN python3 -m pip install --break-system-packages --no-cache-dir \
    ruff \
    vulture \
    schemathesis \
    semgrep \
    pefile \
    defusedxml

ENV HOME=/home/vigil
ENV XDG_CACHE_HOME=/home/vigil/.cache
ENV GOPATH=/home/vigil/go
ENV GOCACHE=/home/vigil/.cache/go-build
ENV PATH="/usr/local/go/bin:/home/vigil/go/bin:/go/bin:/usr/local/bin:$PATH"

# Create writable directories and dedicated non-root vigil user
RUN groupadd -g 1000 vigilgroup 2>/dev/null || true && \
    useradd -u 1000 -g 1000 -d /home/vigil -s /bin/bash vigiluser 2>/dev/null || true && \
    mkdir -p /home/vigil/.cache/go-build /home/vigil/go /workspace /tools/vigil /go && \
    chown -R 1000:1000 /home/vigil && \
    chmod -R 777 /home/vigil && \
    chmod -R 777 /go && \
    chmod -R 777 /workspace

# Copy Vigil internals
COPY . /tools/vigil/
RUN chmod +x /tools/vigil/vigil.sh \
             /tools/vigil/entrypoint.sh \
             /tools/vigil/bin/vigil \
             /tools/vigil/runners/*.sh \
             /tools/vigil/engine/vapt/*.sh \
             /tools/vigil/engine/code_review/*.sh \
             /tools/vigil/engine/anti_fabrication/*.py \
             /tools/vigil/engine/vapt/*.py \
             /tools/vigil/engine/code_review/*.py \
             /tools/vigil/engine/synthesizer/parse_results.py

WORKDIR /workspace

# Healthcheck validating Vigil CLI availability
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/tools/vigil/bin/vigil", "--help"]

USER 1000:1000

ENTRYPOINT ["/tools/vigil/entrypoint.sh"]
CMD ["review"]
