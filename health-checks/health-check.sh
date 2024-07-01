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

# The script performs a health check on the Postgres database.
# This includes:
# - Checking the user running the script
# - Checking the lock file
# - Checking the PGDATA owner
# - Checking the PGDATA permissions
# - Checking the service status
# - Checking the connection to the database
# - Getting the number of CPUs
# - Getting the memory details
# - Getting the disk details
# - Getting the service status
# - Getting the Postgres version
# - Getting all settings
# - Getting role attributes
# - Getting user grants
# - Getting tables not vacuumed for 7 days
# - Getting unused indexes
# - Getting index utilization
# - Getting vacuum stats
# - Getting transaction wraparound
# - Getting permission mask
# - Getting config files
#

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

. ./queries.sh
#
# Set print functions for colored output.
#
blue=$(tput setaf 5)
green=$(tput setaf 2)
red=$(tput setaf 1)
yellow=$(tput setaf 3)
normal=$(tput sgr0)

function print_color() {
  local color=$1
  local message=$2
  printf "%s" "${color}${message}${normal}"
}

function info() {
  printf "[ $(print_color "${blue}" INFO) ] %4s\n" "$1"
}

function warn() {
  printf "[ $(print_color "${yellow}" WARNING) ] %4s\n" "$1"
}

function err() {
  printf "[ $(print_color "${red}" ERROR) ]   %4s\n" "$1"
  exit 1
}

function expect() {
  printf "$(print_color "${blue}" EXPECTED:) %4s\n" "$1"
}

function ok() {
  printf "[ $(print_color "${green}" OK) ] %4s\n" "$1"
}

#
# Set the log file path and also redirect stdout and stderr to
# the log file as well as the console.
#
OUTPUT_DIR=/tmp/health-check
SCRIPT_NAME=$(basename "$0")
SCRIPT_PREFIX="${SCRIPT_NAME%.*}"
LOG_FILE="${OUTPUT_DIR}/${SCRIPT_PREFIX}_$(date +%Y%m%d%H%M%S).log"
LOCK_FILE="${OUTPUT_DIR}/${SCRIPT_PREFIX}.lock"
OUTPUT_PIPE="${OUTPUT_DIR}/${SCRIPT_PREFIX}.pipe"

function init() {
  if [ ! -d "${OUTPUT_DIR}" ]; then
    mkdir -p "${OUTPUT_DIR}"
  else
    rm -rf "${OUTPUT_DIR:?}"/*
  fi
  lock
  mkfifo "${OUTPUT_PIPE}"
  tee -a "${LOG_FILE}" <"${OUTPUT_PIPE}" &
  exec 3>&1 4>&2 >"${OUTPUT_PIPE}" 2>&1
}

function lock() {
  local timestamp
  local pid
  pid=$$
  timestamp=$(date)
  if [ -e "${LOCK_FILE}" ]; then
    err "Lock file exists at ${LOCK_FILE}: exiting"
  fi
  trap cleanup INT TERM HUP EXIT
  echo "${timestamp} ${pid}" >"${LOCK_FILE}"
}

function cleanup() {
  exec 1>&3 3>&- 2>&4 4>&-
  test -e "${LOCK_FILE}" && rm -f "${LOCK_FILE}"
  test -e "${OUTPUT_PIPE}" && rm -f "${OUTPUT_PIPE}"
}

parse_params() {
  while getopts p:d:h: arg; do
    case $arg in
    p)
      PGPORT="$OPTARG"
      ;;
    h)
      PGHOST="${OPTARG}"
      ;;
    ?)
      usage
      ;;
    esac
  done

  if [ -z "$PGPORT" ] || [ -z "$PGHOST" ]; then
    info "Using default values for PGPORT and PGHOST."
    info "PGPORT: ${PGPORT}."
    info "PGHOST: ${PGHOST}."
  fi
  shift $((OPTIND - 1))
}

function usage() {
  echo "
        Usage:
            health-check.sh [ -p <PGPORT> | -h <PGHOST> ]

        Options:

            -p      Postgres server listener port.

            -h      Postgres server host.

        Examples:

            health-check.sh -p 5433 -h 10.0.0.1
"
  exit
}

function get_unit() {
  local input=$1
  local unit=$(echo "${input}" | grep -o -E '[a-zA-Z]+')

  case $unit in
  bytes)
    echo "bytes"
    ;;
  KB | kb | Kb | kB)
    echo "kb"
    ;;
  MB | mb | Mb | mB)
    echo "mb"
    ;;
  GB | gb | Gb | gB)
    echo "gb"
    ;;
  TB | tb | Tb | tB)
    echo "tb"
    ;;
  *)
    warn "Unknown size unit: $unit"
    return
    ;;
  esac
}

function get_value() {
  local input=$1
  local value=$(echo "${input}" | grep -o -E '[0-9]+')
  echo $value
}

function get_size() {
  local input=$1
  local unit=$(get_unit "$input")
  local value=$(get_value "$input")

  case $unit in
  bytes)
    echo $(echo "scale=2; $value / 1024 / 1024" | bc)
    ;;
  kb)
    echo $(echo "scale=2; $value / 1024" | bc)
    ;;
  mb)
    echo $(echo "scale=2; $value" | bc)
    ;;
  gb)
    echo $(echo "scale=2; $value * 1024" | bc)
    ;;
  tb)
    echo $(echo "scale=2; $value * 1024 * 1024" | bc)
    ;;
  *)
    warn "Unknown size unit: $unit"
    return
    ;;
  esac
}

function check_run_user() {
  print_section "Check User"

  if [ "$(whoami)" = "postgres" ] || [ "$(whoami)" = "root" ]; then
    ok "Running as $(whoami) user"
  else
    err "Please run as postgres user or root"
  fi
}

#
# Set default values for PostgreSQL variables.
#
DEFAULT_PGHOST=localhost
DEFAULT_PGUSER=postgres
DEFAULT_PGPORT=5432
DEFAULT_PGVERSION=15

#
# Set the Postgres variables.
#
PGVERSION="${PGVERSION:-"${DEFAULT_PGVERSION}"}"
PGHOST="${PGHOST:-"${DEFAULT_PGHOST}"}"
PGUSER="${PGUSER:-"${DEFAULT_PGUSER}"}"
PGPORT="${PGPORT:-"${DEFAULT_PGPORT}"}"
PGOPTS="${PGOPTS:-"--host ${PGHOST} --port ${PGPORT} --user ${PGUSER}"}"
PGARGS="${PGARGS:-"-At -c"}"
PGARGS_READABLE="${PGARGS_READABLE:-"-c"}"

USER=postgres
DBS=""

OUTPUT_REPORT="${OUTPUT_DIR}/health-check-report.adoc"

#
# Hardware Resources
#
function check_resources() {
  print_section "Check Resources"
  get_cpu
  get_memory
  get_disk
  disk_alert
}

function get_cpu() {
  local output_file="${OUTPUT_DIR}/cpus.txt"
  nproc >"${output_file}"
  info "Number of CPUs: $(cat ${output_file})."
}

function get_memory() {
  local output_file="${OUTPUT_DIR}/memory.txt"
  output=$(free -m)
  total_memory=$(echo "$output" | awk '/^Mem:/ {print $2}')
  used_memory=$(echo "$output" | awk '/^Mem:/ {print $3}')
  free_memory=$(echo "$output" | awk '/^Mem:/ {print $4}')
  buff_cache_memory=$(echo "$output" | awk '/^Mem:/ {print $6}')
  echo "" >"${output_file}"
  free -m >>"${output_file}"
  info "Total Memory: ${total_memory} MB."
  info "Used Memory: ${used_memory} MB."
  info "Free Memory: ${free_memory} MB."
  info "Buffer/Cache Memory: ${buff_cache_memory} MB."
}

function get_disk() {
  local output_file="${OUTPUT_DIR}/disk.txt"
  df -h >>"${output_file}"
  info "Disk details saved to ${output_file}."
}

function disk_alert() {
  local threshold=80
  local over_threshold=0

  df_output=$(df -h --output=pcent,target | tail -n +2)

  while IFS= read -r line; do
    usage=$(echo $line | awk '{print $1}' | tr -d '%')
    mount_point=$(echo $line | awk '{print $2}')

    if [ "$usage" -gt "$threshold" ]; then
      warn "Filesystem $mount_point is over ${threshold}% usage: ${usage}%"
      over_threshold=1
    fi
  done <<<"$df_output"

  if [ $over_threshold -eq 0 ]; then
    ok "There are no disk space alert. All filesystems are below ${threshold}% usage."
  fi
}

#
# Service
#
function check_service() {
  print_section "Check Service"
  get_service_name
  get_service_status
  service_is_enabled
}

function get_service_name() {
  service_file=$(find /etc/systemd/system /usr/lib/systemd/system -name "postgresql*service")
  if [ -z "$service_file" ]; then
    warn "Postgresql service file not found."
  fi
  info "Service file: ${service_file}."
  service=${service_file##*/}
}

function get_service_status() {
  local output_file
  output_file="${OUTPUT_DIR}/service_status.txt"
  systemctl status "${service}" &>"${output_file}" || true
  info "Service status saved to ${output_file}."
}

function service_is_enabled() {
  if systemctl is-enabled "${service}" &>/dev/null; then
    info "PostgreSQL service is enabled."
  else
    warn "PostgreSQL service is not enabled."
  fi
}

#
# Check instance is running
#
function check_connection() {
  print_section "Check Connection"
  if ! pg_isready ${PGOPTS} >/dev/null; then
    err "Cannot connect to the database."
  fi
  ok "Connected to the database."
}

#
# Check PGDATA
#
function check_pgdata() {
  print_section "Check PGDATA"
  get_config_files
  check_pgdata_owner
  check_pgdata_permissions
  get_permission_mask
}

function get_config_files() {
  find "${PGDATA}" -maxdepth 1 -type f -name "*.conf" -print0 | xargs -0 -I {} cp {} "${OUTPUT_DIR}/"
  if [ $? -eq 0 ]; then
    info "Config files copied to ${OUTPUT_DIR}."
  else
    warn "Error copying config files."
  fi
}

function get_data_directory() {
  PGDATA=$(psql ${PGOPTS} ${PGARGS} "SHOW data_directory;")
}

function check_pgdata_owner() {
  local owner
  owner=$(stat -c '%U' "$PGDATA")
  if [ "$owner" = "postgres" ]; then
    ok "Postgresql data is owned by postgres."
  else
    warn "Postgresql data is owned by $owner."
  fi
}

function check_pgdata_permissions() {
  local permissions
  permissions=$(stat -c '%a' "$PGDATA")
  if [ "$permissions" = "700" ] || [ "$permissions" = "600" ]; then
    ok "Postgresql data has 600 or 700 permissions."
  else
    warning "Postgresql data has $permissions permissions."
  fi
}

function get_permission_mask() {
  print_section "Get Permission Mask"
  wrong_permission=$(find "${PGDATA}" \( -type f ! -perm 600 \) -o \( -type d ! -perm 700 \))
  if [ -z "${wrong_permission}" ]; then
    ok "All files and directories have correct permissions."
  else
    for f in ${wrong_permission}; do
      warn "Wrong permission for file: ${f}"
    done
  fi
}

#
# Get Instance Details
#
function get_instance_details() {
  print_section "Get Instance Details"
  get_databases
  get_version
  get_all_settings
}

function get_databases() {
  DBS=$(psql ${PGOPTS} ${PGARGS} "SELECT datname FROM pg_database WHERE datistemplate = false and datname <> 'postgres';" | awk NF)
  for db in ${DBS}; do
    info "Database: ${db}"
    mkdir -p "${OUTPUT_DIR}/${db}"
  done
}

function get_version() {
  print_section "Get PostgreSQL Version"
  local output_file="${OUTPUT_DIR}/version.txt"
  psql ${PGOPTS} ${PGARGS} "SELECT version();" >>"${output_file}"
  info "$(cat ${output_file})"
  info "Major Version: $(psql ${PGOPTS} ${PGARGS} "SELECT current_setting('server_version_num');")"
}

function get_all_settings() {
  print_section "Get All Settings"
  local output_file="${OUTPUT_DIR}/all_settings.txt"
  psql ${PGOPTS} ${PGARGS} "SELECT name, setting, unit FROM pg_settings;" >"${output_file}"
  info "All settings saved to ${output_file}."
}

#
# Logging Checks
#
function check_logging() {
  print_section "Logging"
  check_log_collector
  check_log_destination
  check_log_directory
  check_log_file_mode
  check_log_truncate
  check_max_log_size
}

function check_log_collector() {
  local log_collector
  log_collector=$(psql ${PGOPTS} ${PGARGS} "SHOW logging_collector;")
  if [[ -z "${log_collector// /}" ]]; then
    warn "Log collector not set"
  else
    ok "Log collector is set to '${log_collector}'."
  fi
}

function check_log_destination() {
  local log_destination
  log_destination=$(psql ${PGOPTS} ${PGARGS} "SHOW log_destination;")
  if [[ -z "${log_destination// /}" ]]; then
    warn "Log destination not set."
  else
    ok "Log destination is set to '${log_destination}'."
  fi
}

function check_log_directory() {
  local log_directory
  log_directory=$(psql ${PGOPTS} ${PGARGS} "SHOW log_directory;")
  if [[ -z "${log_directory// /}" ]]; then
    warn "Log directory not set"
  else
    ok "Log directory is set to $log_directory"
  fi
}

function check_log_file_mode() {
  local log_file_mode
  log_file_mode=$(psql ${PGOPTS} ${PGARGS} "SHOW log_file_mode;")
  if [[ "${log_file_mode// /}" != "0600" ]]; then
    warn "Log file mode not 0600"
  else
    ok "Log file mode is set to $log_file_mode"
  fi

}

function check_log_truncate() {
  local log_truncate
  log_truncate=$(psql ${PGOPTS} ${PGARGS} "SHOW log_truncate_on_rotation;")
  if [[ "${log_truncate// /}" != "on" ]]; then
    warn "Log truncate not on"
  else
    ok "Log truncate is set to $log_truncate"
  fi
}

function check_max_log_size() {
  local max_log_size
  max_log_size=$(psql ${PGOPTS} ${PGARGS} "SHOW log_rotation_size;")
  max_log_size=$(get_size "${max_log_size}")
  if [[ ${max_log_size} -le 10 ]]; then
    warn "Log rotation size less than 10MB"
  else
    ok "Log rotation size is set to $max_log_size"
  fi
}

#
# Check User and Role Privileges
#
function check_user_privileges() {
  print_section "Check User Privileges"
  get_role_attributes
  get_user_grants
  get_user_permissions
  check_function_privileges
  check_replication_user
}

function get_role_attributes() {
  local output_file="${OUTPUT_DIR}/role_attributes.txt"
  psql ${PGOPTS} ${PGARGS_READABLE} "${SQL_ROLE_ATTRIBUTES}" >"${OUTPUT_DIR}/role_attributes.txt"
  cat ${output_file} | grep -v postgres
}

function get_user_grants() {
  print_section "Get User Grants"
  local output_file="${OUTPUT_DIR}/user_grants.txt"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS_READABLE} "${SQL_GRANTS}" >"${OUTPUT_DIR}/${db}/user_grants.txt"
    info "User grants for database ${db} saved to ${OUTPUT_DIR}/${db}/user_grants.txt."
  done
}

function get_user_permissions() {
  print_section "Get User Permissions and Privileges"
  local output_file="${OUTPUT_DIR}/user_permissions.txt"
  psql ${PGOPTS} ${PGARGS_READABLE} "${USER_PERMISSIONS}" >"${OUTPUT_DIR}/user_permissions.txt"
  info "User permissions saved to ${output_file}."
}

function check_function_privileges() {
  excessive=$(psql ${PGOPTS} ${PGARGS} "${PRIVILEGES}")

  if [ -z "$excessive" ]; then
    ok "No excessive function privileges granted"
  else
    warn "Excessive function privileges granted:"
    echo "$excessive"
  fi
}

function check_replication_user() {
  repluser=$(psql ${PGOPTS} ${PGARGS} "${REPLICATION_USER}")

  if [ -z "$repluser" ]; then
    warn "No dedicated replication user found"
  else
    ok "Dedicated replication user exists: $repluser"
  fi
}

#
# Vacuuming
#
function check_vacuum() {
  print_section "Check Vacuum"
  get_not_vacuumed
  get_vacuum_stats
  get_transaction_wraparound
}

function get_not_vacuumed() {
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS_READABLE} "${SQL_NOT_VACUUMED}" >"${OUTPUT_DIR}/${db}/not_vacuumed.txt"
    info "Tables not vacuumed for 7 days in database ${db} saved to ${OUTPUT_DIR}/${db}/not_vacuumed.txt."
  done
}

function get_vacuum_stats() {
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_VACUUM_STATS}" >"${OUTPUT_DIR}/${db}/vacuum_stats.txt"
    info "Vacuum stats in database ${db} saved to ${OUTPUT_DIR}/${db}/vacuum_stats.txt."
  done
}

function get_transaction_wraparound() {
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_TRANSACTION_WRAPAROUND}" >"${OUTPUT_DIR}/${db}/transaction_wraparound.txt"
    info "Transaction wraparound in database ${db} saved to ${OUTPUT_DIR}/${db}/transaction_wraparound.txt."
  done
}

#
# Indexes
#
function check_indexes() {
  print_section "Check Indexes"
  get_unused_indexes
  get_duplicate_indexes
  get_index_utiliation
  get_largest_tables
}

function get_unused_indexes() {
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_UNUSED_INDEXES}" >"${OUTPUT_DIR}/${db}/unused_indexes.txt"
    info "Unused indexes in database ${db} saved to ${OUTPUT_DIR}/${db}/unused_indexes.txt."
  done
}

function get_duplicate_indexes() {
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_DUPLICATE_INDEXES}" >"${OUTPUT_DIR}/${db}/duplicate_indexes.txt"
    info "Duplicate indexes in database ${db} saved to ${OUTPUT_DIR}/${db}/duplicate_indexes.txt."
  done
}

function get_index_utiliation() {
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_INDEX_UTILIZATION}" >"${OUTPUT_DIR}/${db}/index_utilization.txt"
    info "Index utilization in database ${db} saved to ${OUTPUT_DIR}/${db}/index_utilization.txt."
  done
}

function get_largest_tables() {
  print_section "Get Largest Tables"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_LARGEST_TABLES}" >"${OUTPUT_DIR}/${db}/largest_tables.txt"
    info "Largest tables in database ${db} saved to ${OUTPUT_DIR}/${db}/largest_tables.txt."
  done
}

function check_packages() {
  print_section "Check Packages"
  check_authorized_repos
  check_pgaudit_enabled
}

function get_os() {
  print_section "Get OS"
  local os
  os="$(cat /etc/os-release)"
  info "OS: $os"
  echo "$os"
}

function check_authorized_repos() {
  if [ -f /etc/redhat-release ]; then
    check_redhat_repos
  elif [ -f /etc/debian_version ]; then
    check_debian_repos
  elif [ -f /etc/arch-release ]; then
    check_arch_repos
  else
    warn "Unknown OS"
  fi
}

function check_redhat_repos() {
  local os_user
  os_user="$(whoami)"
  if [ "$os_user" != "root" ]; then
    warn "Please run as root"
    return
  fi

  while read -r line; do
    info "$line"
  done < <(dnf info "$(rpm -qa | grep postgres)" | grep -E '^Name|^Version|^From')
}

function check_debian_repos() {
  local os_user
  os_user="$(whoami)"
  if [ "$os_user" != "root" ]; then
    warn "Please run as root"
    return
  fi

  local installed_packages
  installed_packages=$(dpkg-query -W -f='${binary:Package}\n' | grep -i postgres)

  for package in $installed_packages; do
    info "Package: $package"
    version=$(dpkg-query -W -f='${Version}\n' $package)
    info "Version: $version"
    from_repo=$(apt-cache policy $package | grep -E '^\s*500\s*http' | head -n 1 | awk '{print $3}')
    info "From: $from_repo"
    echo
  done
}

function check_arch_repos() {
  expected_repo="extra"
  if pacman-conf --repo-list | grep -q "${expected_repo}"; then
    ok "Packages obtained from authorized repositories"
  else
    warn "Packages not obtained from authorized repositories"
  fi
}

function check_pgaudit_enabled() {
  extensions=$(psql ${PGOPTS} ${PGARGS} "SELECT * FROM pg_available_extensions WHERE name='pgaudit';" | grep pgaudit)

  if [ -z "$extensions" ]; then
    warn "pgaudit extension is not enabled"
  else
    ok "pgaudit extension is enabled"
  fi
}

#
# Functions for checking connections
#
function check_connections() {
  print_section "Check Connections"
  check_local_connection
  check_host_connection
}

function check_local_connection() {
  local_auth=$(grep '^local' $PGDATA/pg_hba.conf)

  if echo "$local_auth" | grep -q 'peer'; then
    ok "Local connections use 'peer' authentication"
  else
    warn "Local connections not using 'peer' authentication"
  fi
}

function check_host_connection() {
  host_auth=$(grep '^host' $PGDATA/pg_hba.conf)

  if echo "$host_auth" | grep -q 'scram-sha-256'; then
    ok "Host connections use 'scram-sha-256' authentication"
  else
    warn "Host connections not using 'scram-sha-256' authentication"
  fi
}

#
# Functions for checking replication
#
function check_replication() {
  print_section "Check Replication"
  check_replication_logging
  check_wal_archive
  check_replication_params
  local is_slave=$(psql ${PGOPTS} ${PGARGS} "${IS_SLAVE}")
  if [ "${is_slave}" = "f" ]; then
    info "This is a read/write instance."
    get_replication_stats_primary
    get_replication_slots
  else
    info "This is a standby."
    get_replication_stats_standby
    get_replication_lag
  fi
}

function check_replication_logging() {
  print_section "Check Replication Logging"
  log_level=$(psql ${PGOPTS} ${PGARGS} "SHOW log_replication_commands;")

  if [ "$log_level" = "on" ]; then
    ok "Replication command logging is enabled"
  else
    warn "Replication command logging is not enabled"
  fi
}

function check_wal_archive() {
  print_section "Check WAL Archiving"
  archive_mode=$(psql ${PGOPTS} ${PGARGS} "SHOW archive_mode;")
  archive_command=$(psql ${PGOPTS} ${PGARGS} "SHOW archive_command;")

  if [ "$archive_mode" = "on" ] && [ -n "$archive_command" ]; then
    ok "WAL archiving is enabled and configured"
  else
    warn "WAL archiving is not enabled or configured"
  fi
}

function check_replication_params() {
  print_section "Check Replication Parameters"
  params=$(psql ${PGOPTS} ${PGARGS} "
        SELECT name, setting 
        FROM pg_settings  
        WHERE name IN ('max_wal_senders', 'wal_keep_segments');
    ")

  if echo "$params" | grep -q "max_wal_senders | [1-9]"; then
    ok "max_wal_senders is configured"
  else
    warn "max_wal_senders is not properly configured"
  fi

  if echo "$params" | grep -q "wal_keep_segments | [1-9]"; then
    ok "wal_keep_segments is configured"
  else
    warn "wal_keep_segments is not properly configured"
  fi
}

function get_replication_stats_primary() {
  if [ "$(psql ${PGOPTS} ${PGARGS} 'SELECT count(*) FROM pg_stat_replication')" -eq 0 ]; then
    warn "No replication configured."
  else
    psql ${PGOPTS} ${PGARGS_READABLE} "${REPLICATION_STATS_PRIMARY}" >"${OUTPUT_DIR}/replication_stats.txt"
    info "Replication stats saved to ${OUTPUT_DIR}/replication_stats.txt."
  fi
}

function get_replication_stats_standby() {
  if [ "$(psql ${PGOPTS} ${PGARGS} "SELECT count(*) FROM pg_stat_wal_receiver")" -eq 0 ]; then
    warn "No replication configured."
    return
  else
    psql ${PGOPTS} ${PGARGS_READABLE} "${REPLICATION_STATS_STANDBY}" >"${OUTPUT_DIR}/replication_stats.txt"
    info "Replication stats saved to ${OUTPUT_DIR}/replication_stats.txt."
  fi
}

function get_replication_slots() {
  if [ $(psql ${PGOPTS} ${PGARGS} "SELECT count(*) FROM pg_replication_slots") -eq 0 ]; then
    warn "No replication slots configured."
    return
  else
    psql ${PGOPTS} ${PGARGS} "${REPLICATION_SLOTS}" >"${OUTPUT_DIR}/replication_slots.txt"
    info "Replication slots in database ${db} saved to ${OUTPUT_DIR}/replication_slots.txt."
  fi
}

function get_replication_lag() {
  psql ${PGOPTS} ${PGARGS} "${REPLICATION_LAG}" >"${OUTPUT_DIR}/replication_lag.txt"
  info "Replication lag saved to ${OUTPUT_DIR}/replication_lag.txt."
}

#
# Function for checking encryption
#
function check_encryption() {
  print_section "Check Encryption"
  check_pgcrypto
}

function check_pgcrypto() {
  extensions=$(psql ${PGOPTS} -c "SELECT * FROM pg_available_extensions WHERE name='pgcrypto';" | grep pgcrypto)

  if [ -z "$extensions" ]; then
    warn "pgcrypto extension is not installed"
  else
    ok "pgcrypto extension is installed"
  fi
}

function print_section_console() {
  local width=80
  local sep="-"
  local title=" $1 "
  local title_length=${#title}
  local total_padding=$((width - title_length))
  local padding_left=$((total_padding / 2))
  local padding_right=$((total_padding - padding_left))
  printf "\n%*s" $padding_left | tr " " "$sep"
  printf "%s" "$title"
  printf "%*s\n" $padding_right | tr " " "$sep"

}

function print_subsection_console() {
  local width=80
  local sep="."
  local title=" $1 "
  local start_column=$((width / 4))
  local title_length=${#title}
  local total_padding=$((width - title_length - start_column * 2))
  local padding_left=$((total_padding / 2))
  local padding_right=$((total_padding - padding_left))
  printf "\n%*s %s \n" $start_column $title
}

function print_section_report() {
  local title=$1
  echo "=== $title" >>"${OUTPUT_REPORT}"
}

function print_subsection_report() {
  local title=$1
  echo "==== $title" >>"${OUTPUT_REPORT}"
}

function print_section() {
  print_section_console "$1"
  print_section_report "$1"
}

function print_subsection() {
  print_subsection_console "$1"
  print_subsection_report "$1"
}

function log_cleanup() {
  sed -i 's/\x1b\[[0-9;]*m//g' "${LOG_FILE}"
  sed -i 's/\x1b(B//g' "${LOG_FILE}"
}

function main() {
  init
  parse_params
  check_run_user
  get_data_directory
  check_resources
  check_service
  check_connection
  check_pgdata
  get_instance_details
  check_logging
  check_vacuum
  check_indexes
  check_packages
  check_connections
  check_replication
  check_encryption
  log_cleanup
}

main
