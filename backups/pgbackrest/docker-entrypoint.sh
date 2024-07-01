#!/bin/bash
set -e

# This script is executed with postgres user privileges

# Path to the PostgreSQL data directory
PGDATA="/var/lib/postgresql/15/main"

# Path to the PostgreSQL configuration file
PGCONF="/var/lib/postgresql/15/main/postgresql.conf"

if [ -d $PGDATA ]; then
    rm -rf $PGDATA
fi

if [ "$POSTGRES_REPLICATION_ROLE" = "primary" ]; then
    /usr/lib/postgresql/15/bin/initdb -D $PGDATA
    echo "listen_addresses = '*'" >>"${PGCONF}"
    echo "archive_mode = 'on'" >>"${PGCONF}"
    echo "archive_command = '/bin/true'" >>"${PGCONF}"
    echo "log_directory = '/var/log/postgresql'" >>"${PGCONF}"
    echo "log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'" >>"${PGCONF}"
    echo "log_statement = 'all'" >>"${PGCONF}"
    echo "log_destination = 'stderr'" >>"${PGCONF}"
    echo "log_min_messages = 'info'" >>"${PGCONF}"
    echo "log_min_error_statement = 'error'" >>"${PGCONF}"
    echo "log_line_prefix = '%m [%p] %q%u@%d'" >>"${PGCONF}"
    echo "logging_collector = 'on'" >>"${PGCONF}"

    echo "host all all 0.0.0.0/0 trust" >>"${PGDATA}/pg_hba.conf"
    echo "host replication all 0.0.0.0/0 trust" >>"${PGDATA}/pg_hba.conf"
fi

if [ "$POSTGRES_REPLICATION_ROLE" = "replica" ]; then
    until pg_isready -h $POSTGRES_PRIMARY_HOST -p $POSTGRES_PRIMARY_PORT -U $POSTGRES_REPLICATION_USER &>/dev/null; do
        echo "Waiting for the PostgreSQL primary server to accept connections..."
        sleep 1
    done
    pg_basebackup -h $POSTGRES_PRIMARY_HOST -D $PGDATA -U $POSTGRES_REPLICATION_USER -v -R -C -S $(hostname) -P --wal-method=stream
    touch "${PGDATA}/standby.signal"
    echo "primary_conninfo = 'host=${POSTGRES_PRIMARY_HOST} port=${POSTGRES_PRIMARY_PORT} user=${POSTGRES_REPLICATION_USER} password=${POSTGRES_REPLICATION_PASSWORD}'" >>"${PGCONF}"
    echo "primary_slot_name = '${POSTGRES_REPLICATION_SLOT}'" >>"${PGCONF}"
fi

exec "/usr/lib/postgresql/15/bin/postgres" "-D" "${PGDATA}" "-c" "config_file=${PGCONF}" &
tail -f /dev/null
