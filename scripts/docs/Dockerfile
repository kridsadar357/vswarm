# The demo machine for docs screenshots and Linux tests: Debian with Bun, bubblewrap, strace, sshd and zsh.
FROM oven/bun:1.3.0
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap strace git openssh-client openssh-server zsh procps iproute2 ca-certificates python3 nodejs && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash dev && mkdir -p /home/dev/.ssh && ssh-keygen -q -t ed25519 -N "" -f /home/dev/.ssh/id_ed25519 && chown -R dev:dev /home/dev
USER dev
WORKDIR /home/dev
