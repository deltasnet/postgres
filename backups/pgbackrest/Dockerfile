# Use Ubuntu as the base image
FROM ubuntu:latest

# Avoid prompts from debconf, including tzdata
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages for repository management and downloading keys
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    lsb-release \
    debconf-utils \
    && echo 'tzdata tzdata/Areas select Europe' | debconf-set-selections \
    && echo 'tzdata tzdata/Zones/Europe select Berlin' | debconf-set-selections \
    && rm -rf /var/lib/apt/lists/*

# Download and save the PostgreSQL signing key
RUN wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/pgdg-archive-keyring.gpg

# Add PostgreSQL's repository using the saved keyring
RUN echo "deb [signed-by=/usr/share/keyrings/pgdg-archive-keyring.gpg] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list

# Update APT sources and install PostgreSQL 15
RUN apt-get update && apt-get install -y postgresql-15 \
    && rm -rf /var/lib/apt/lists/*

# Install additional required packages
RUN apt-get update && apt-get install -y \
    openssh-client \
    openssh-server \
    pgbackrest \
    sudo \
    vim && rm -rf /var/lib/apt/lists/*

# Setup SSH (simplified setup; not recommended for production use)
RUN mkdir /var/run/sshd \
    && echo 'root:root' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

COPY ./pgbackrest.conf /etc/pgbackrest.conf
RUN chown postgres:postgres /etc/pgbackrest.conf
RUN mkdir /backup && chown postgres:postgres /backup


# Reset DEBIAN_FRONTEND to its default value for further commands and container runtime
ENV DEBIAN_FRONTEND=

COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5432 22

RUN mkdir /var/lib/postgresql/.ssh && chmod 700 /var/lib/postgresql/.ssh
COPY id_rsa /var/lib/postgresql/.ssh/id_rsa
COPY id_rsa.pub /var/lib/postgresql/.ssh/id_rsa.pub
RUN echo "Host *\n\tStrictHostKeyChecking no\n\n" > /var/lib/postgresql/.ssh/config
RUN cat /var/lib/postgresql/.ssh/id_rsa.pub > /var/lib/postgresql/.ssh/authorized_keys
RUN chmod 600 /var/lib/postgresql/.ssh/id_rsa && chmod 644 /var/lib/postgresql/.ssh/id_rsa.pub && chown -R postgres:postgres /var/lib/postgresql/.ssh
RUN /usr/sbin/sshd -D &

USER postgres

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]