FROM rust:1.85

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/*.list /etc/apt/sources.list 2>/dev/null || true

RUN apt-get update && apt-get install -y -qq \
    llvm-dev \
    clang \
    libelf-dev \
    libbpf-dev \
    ca-certificates \
    curl \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# nightly 工具链用于 eBPF 编译，与预编译 bpf-linker 的 LLVM 版本保持一致。
# 本地 rust-toolchain.toml 中的 stable 仅用于用户态 ariactl 编译，两者互不冲突。
ARG BPF_LINKER_VERSION=0.10.4
ARG BPF_LINKER_X86_64_SHA256=4dda77daab6c5f120a468e6d3ede2498f5bd47ece712172cfb7290176d93d015
ARG BPF_LINKER_AARCH64_SHA256=c3638cd3cb735ff85705905a07e0df61c0f9426480334c8e2efe5cb92fd9d3de
ARG TARGETARCH
RUN build_arch="${TARGETARCH:-$(uname -m)}" && \
    case "${build_arch}" in \
      amd64|x86_64) bpf_linker_arch=x86_64; bpf_linker_sha256="${BPF_LINKER_X86_64_SHA256}" ;; \
      arm64|aarch64) bpf_linker_arch=aarch64; bpf_linker_sha256="${BPF_LINKER_AARCH64_SHA256}" ;; \
      *) echo "unsupported builder architecture: ${build_arch}" >&2; exit 1 ;; \
    esac && \
    rustup toolchain install nightly-2026-07-14 --profile minimal --component rust-src && \
    rustup default nightly-2026-07-14 && \
    curl --fail --location --retry 3 --retry-all-errors \
      "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-${bpf_linker_arch}-unknown-linux-musl.tar.zst" \
      --output /tmp/bpf-linker.tar.zst && \
    echo "${bpf_linker_sha256}  /tmp/bpf-linker.tar.zst" | sha256sum --check --strict && \
    tar --zstd --extract --file /tmp/bpf-linker.tar.zst --directory /usr/local/cargo/bin && \
    rm /tmp/bpf-linker.tar.zst && \
    bpf-linker --version

WORKDIR /workspace

CMD ["bash"]
