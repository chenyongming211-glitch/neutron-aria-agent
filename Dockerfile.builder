FROM rust:1.85

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/*.list /etc/apt/sources.list 2>/dev/null || true

RUN apt-get update && apt-get install -y -qq \
    llvm-dev \
    clang \
    libelf-dev \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-gnu && \
    rustup toolchain install nightly-x86_64-unknown-linux-gnu --profile minimal --component rust-src --force-non-host && \
    rustup default nightly-x86_64-unknown-linux-gnu && \
    cargo install bpf-linker

WORKDIR /workspace

CMD ["bash"]
