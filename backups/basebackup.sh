#!/usr/bin/env bash

# Copyright 2024 DeltaSoft Solutions LTD.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The script performs a backup on standby server and cleanup the old backups
# based on the retention period.
# Old archive logs are also cleaned up based on the retention period.

# Variables which can be overridden:
#
# - PGHOST: Postgres host
# - PGUSER: Postgres user
# - PGPORT: Postgres port
# - PGVERSION: Postgres version
# - PGROOT: Postgres root directory
# - PGBIN: Postgres bin directory
# - PGDATA: Postgres data directory
# - BACKUPDIR: Backup directory

set -o errexit
set -o nounset
set -o pipefail

function err() {
    printf "[%s]: %s\n" "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$*" >&2
    exit 1
}

function info() {
    printf "[%s]: %s\n" "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$*" >&1
}

#####
#
# Set the log file path and also redirect stdout and stderr to
# the log file as well as the console.
#
#####
SCRIPT_NAME=$(basename "$0")
SCRIPT_PREFIX="${SCRIPT_NAME%.*}"
LOG_FILE="/tmp/${SCRIPT_PREFIX}_$(date +%Y%m%d%H%M%S).log"
LOCK_FILE="/tmp/${SCRIPT_PREFIX}.lock"

#####
#
# Set the default values for the Postgres variables.
#
#####
DEFAULT_PGHOST=localhost
DEFAULT_PGUSER=postgres
DEFAULT_PORT=5432
DEFAULT_PGVERSION="$(postgres --version | awk '{print $3}' | cut -d '.' -f 1)"

#####
#
# Set the Postgres variables.
#
#####
PGVERSION="${PGVERSION:-"${DEFAULT_PGVERSION}"}"
PGHOST="${PGHOST:-"${DEFAULT_PGHOST}"}"
PGUSER="${PGUSER:-"${DEFAULT_PGUSER}"}"
PGPORT="${PGPORT:-"${DEFAULT_PORT}"}"
PGOPTIONS="${PGOPTIONS:-"--host ${PGHOST} --port ${PGPORT} --user ${PGUSER}"}"

BACKUPPREFIX="pgsql"
BACKUPNAME="${BACKUPPREFIX}-$(date +\%y\%m\%d\%H\%M)"
BACKUPOPTIONS="--pgdata=${BACKUPDIR}/${BACKUPNAME} --format=t --gzip --compress=5 -P"
ARCHIVE_LOCATION=${PGHOME}/archive_wal
RETENTION=14
IS_RECOVERY=""

function check_user() {
    if [ "$(whoami)" != "postgres" ]; then
        err "This script must be run as the 'postgres' user."
    fi
}

function check_lock() {
    local timestamp
    local pid
    timestamp=$(date +%Y%m%d%H%M%S)
    pid=$$
    if [ -e "${LOCK_FILE}" ]; then
        err "Lock file exists: exiting"
        exit 1
    fi
    trap 'rm -f "${LOCK_FILE}"; exit' INT TERM HUP EXIT
    echo "${timestamp} ${pid}" >"${LOCK_FILE}"
}

function check_binaries() {
    if [ -z "${PGBIN}" ]; then
        find_binaries
    fi
}

function check_data_directory() {
    if [ -z "${PGDATA}" ]; then
        find_data_directory
    fi
}

function check_connection() {
    if ! "${PGBIN}/pg_isready" "${PGOPTIONS}" >/dev/null; then
        err "Cannot connect to the database."
    fi
}

function find_binaries() {
    local binaries="pg_basebackup pg_isready psql"
    local found=true
    PGBIN=$(dirname "$(command -v pg_basebackup)")
    for binary in ${binaries}; do
        if command -v "${PGBIN}/${binary}" >/dev/null; then
            info "${binary} found at $(command -v "${binary}")"
        else
            info "${binary} not found in ${PGBIN}. Checking other default locations..."
            found=false
            break
        fi
    done

    if [[ "${found}" == "false" ]]; then
        PGBIN="${DEFAULT_PGBIN}"
        for binary in ${binaries}; do
            if [ -x "${PGBIN}/${binary}" ]; then
                info "${binary} found at ${PGBIN}/${binary}"
            else
                err "${binary} not found"
            fi
        done
    fi
}

function find_data_directory() {
    declare -ag DEFAULT_PGDATA
    readarray -t DEFAULT_PGDATA < <(pgrep -a '[p]ostgres' | grep -- '-D' | awk '{for (i=1; i<=NF; i++) if ($i == "-D" && $(i+1) != "") {print $(i+1)}}')
    if [[ -z "${DEFAULT_PGDATA:-}" ]] || [ "${#DEFAULT_PGDATA[@]}" -gt 1 ]; then
        if [ -z "${DEFAULT_PGDATA}" ]; then
            err "Postgres data directory not found."
        else
            err "Multiple Postgres data directories found."
        fi
    fi
}

function is_recovery() {
    if "${PGBIN}/psql" "${PGOPTIONS}" -At -c "SELECT pg_is_in_recovery()" | grep -q "t"; then
        IS_RECOVERY=true
        info "The database instance is in recovery mode."
    else
        IS_RECOVERY=false
        info "The database instance is in read/write mode."
    fi
}

function is_archive_mode() {
    if "${PGBIN}/psql" "${PGOPTIONS}" -t -c "SHOW archive_mode" | grep -q "on"; then
        IS_ARCHIVE_MODE=true
        info "The database instance is in archive mode."
    else
        IS_ARCHIVE_MODE=false
        info "The database instance is not in archive mode."
    fi
}

function get_archive_directory() {
    if [[ "$ARCHIVE_LOCATION" == "" ]]; then
        ARCHIVE_LOCATION=$("${PGBIN}/psql" "${PGOPTIONS}" -t -c "SHOW archive_command" | awk '{print $2}' | sed 's/\"//g')
    fi
    if [ "${IS_ARCHIVE_MODE}" = "true" ]; then
        ARCHIVE_LOCATION=$("${PGBIN}/psql" "${PGOPTIONS}" -t -c "SHOW archive_command" | awk '{print $2}' | sed 's/\"//g')
    fi
}

function backup() {
    info "Starting backup..."
    "${PGBIN}/pg_basebackup" "${BACKUPOPTIONS}"
    info "Backup completed."
}

function backup_cleanup() {
    info "Starting backup cleanup..."
    if [ -d ${BACKUPDIR} ]; then
        find ${BACKUPDIR:?}/ -maxdepth 1 -name "${BACKUPPREFIX}-*" -ctime +${RETENTION} -exec rm -rf {} \;
    fi
    info "Backup cleanup completed."
}

function archive_cleanup() {
    info "Starting archive cleanup..."
    find ${ARCHIVE_LOCATION:?} -maxdepth 1 -name "*.gz" -ctime +${RETENTION} -exec rm {} \;
    info "Archive cleanup completed."
}

function main() {
    check_user
    check_lock
    check_binaries
    check_data_directory
    is_recovery
    if [ "${IS_RECOVERY}" = "true" ]; then
        backup
        backup_cleanup
    fi
    archive_cleanup
}

main
