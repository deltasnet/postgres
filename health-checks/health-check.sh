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

#####
#
# Set print functions for colored output.
#
#####
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

#####
#
# Set the log file path and also redirect stdout and stderr to
# the log file as well as the console.
#
#####
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
    err "Lock file exists at ${lOCK_FILE}: exiting"
  fi
  trap cleanup INT TERM HUP EXIT
  echo "${timestamp} ${pid}" >"${LOCK_FILE}"
}

function cleanup() {
  exec 1>&3 3>&- 2>&4 4>&-
  test -e "${LOCK_FILE}" && rm -f "${LOCK_FILE}"
  test -e "${OUTPUT_PIPE}" && rm -f "${OUTPUT_PIPE}"
}

####
#
# Set default values for PostgreSQL variables.
#
####
DEFAULT_PGHOST=localhost
DEFAULT_PGUSER=postgres
DEFAULT_PGPORT=5432
DEFAULT_PGVERSION=15

#####
#
# Set the Postgres variables.
#
#####
PGVERSION="${PGVERSION:-"${DEFAULT_PGVERSION}"}"
PGHOST="${PGHOST:-"${DEFAULT_PGHOST}"}"
PGUSER="${PGUSER:-"${DEFAULT_PGUSER}"}"
PGPORT="${PGPORT:-"${DEFAULT_PGPORT}"}"
PGOPTIONS="${PGOPTIONS:-"--host ${PGHOST} --port ${PGPORT} --user ${PGUSER} -At -c"}"

USER=postgres
DBS=""

OUTPUT_REPORT="${OUTPUT_DIR}/health-check-report.adoc"

function check_user() {
  print_section "Check User"

  if [ "$(whoami)" != "postgres" ]; then
    err "Please run as postgres user"
  else
    ok "Running as postgres user"
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

function check_pgdata() {
  print_section "Check PGDATA owner"
  local owner
  owner=$(stat -c '%U' "$PGDATA")
  if [ "$owner" == "postgres" ]; then
    ok "Postgresql data is owned by postgres"
  else
    warn "Postgresql data is owned by $owner"
  fi
}

function check_pgdata_permissions() {
  print_section "Check PGDATA permissions"
  local permissions
  permissions=$(stat -c '%a' "$PGDATA")
  if [ "$permissions" == "700" ] || [ "$permissions" == "600" ]; then
    ok "Postgresql data has 600 or 700 permissions"
  else
    warning "Postgresql data has $permissions permissions"
  fi
}

function check_service() {
  local result
  local service=$(get_service)
  systemctl is-enabled "${service}" &>/dev/null
  result=$?
  if [ $result -eq 0 ]; then
    ok "Postgresql service is enabled"
  else
    warning "Postgresql service is not enabled"
  fi
}

function get_service() {
  local service
  service=$(systemctl list-units --type=service | grep postgresql | awk '{print $1}')
  echo "${service}"
}

function check_connection() {
  if ! "${PGBIN}/pg_isready" ${PGOPTIONS} >/dev/null; then
    err "Cannot connect to the database."
  fi
}

function get_data_directory() {
  PGDATA=$(psql ${PGOPTIONS} "SHOW data_directory;")
}

function get_databases() {
  DBS=$(psql ${PGOPTIONS} "SELECT datname FROM pg_database WHERE datistemplate = false;" | awk NF)
}

function get_cpu() {
  print_section "Number of CPUS"
  local output_file="${OUTPUT_DIR}/cpus.txt"
  nproc >"${output_file}"
  info "Number of CPUs: $(cat ${output_file})"
}

function get_memory() {
  print_section "Memory Details"
  local output_file="${OUTPUT_DIR}/memory.txt"
  echo "" >"${output_file}"
  free -m >>"${output_file}"
  info "$(cat ${output_file})"
}

function get_disk() {
  print_section "Disk Analysis Part 1"
  local output_file="${OUTPUT_DIR}/disk.txt"
  df -h >>"${output_file}"
  info "Disk details saved to ${output_file}"
}

function disk_alert() {
  print_section "Disk Analysis Part 2"
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
    ok "All filesystems are below ${threshold}% usage."
  fi
}

function get_service_status() {
  print_section "Service Status"
  local is_enabled
  local output_file
  output_file="${OUTPUT_DIR}/service_status.txt"
  service_file=$(find /etc/systemd/system -name "postgresql*service")
  if [ -z "${service_file}" ]; then
    service_file=$(find /usr/lib/systemd/system -name "postgresql*service")
  fi
  if [ -z "${service_file}" ]; then
    warn "Postgresql service file not found"
    return
  else
    info "Postgresql service file found at ${service_file}"
  fi
  service=${service_file##*/}
  systemctl status "${service}" >"${output_file}"

  if systemctl is-enabled "${service}" >/dev/null; then
    info "PostgreSQL service is enabled"
  else
    warn "PostgreSQL service is not enabled"
  fi

}

function get_version() {
  print_section "Get PostgreSQL Version"
  local output_file="${OUTPUT_DIR}/version.txt"
  psql ${PGOPTIONS} "SELECT version();" >>"${output_file}"
  info "$(cat ${output_file})"
}

function get_all_settings() {
  print_section "Get All Settings"
  local output_file="${OUTPUT_DIR}/all_settings.txt"
  psql ${PGOPTIONS} "SELECT name, setting, unit FROM pg_settings;" >"${output_file}"
  info "All settings saved to ${output_file}"
}

function get_role_attributes() {
  print_section "Get Role Attributes"
  local output_file="${OUTPUT_DIR}/role_attributes.txt"
  psql ${PGOPTIONS} "${SQL_ROLE_ATTRIBUTES}" >"${OUTPUT_DIR}/role_attributes.txt"
  cat ${output_file} | grep -v postgres
}

function get_user_grants() {
  print_section "Get User Grants"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTIONS} "${SQL_GRANTS}" >"${OUTPUT_DIR}/${db}_user_grants.txt"
  done
}

function get_not_vacuumed() {
  print_section "Get Not Vacuumed for 7 days"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTIONS} "${SQL_NOT_VACUUMED}" >"${OUTPUT_DIR}/${db}_not_vacuumed.txt"
  done
}

function get_unused_indexes() {
  print_section "Get Unused Indexes"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTIONS} "${SQL_UNUSED_INDEXES}" >"${OUTPUT_DIR}/${db}_unused_indexes.txt"
  done
}

function get_duplicate_indexes() {
  print_section "Get Duplicate Indexes"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTIONS} "${SQL_DUPLICATE_INDEXES}" >"${OUTPUT_DIR}/${db}_duplicate_indexes.txt"
  done
}

function get_index_utiliation() {
  print_section "Get Index Utilization"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTIONS} "${SQL_INDEX_UTILIZATION}" >"${OUTPUT_DIR}/${db}_index_utilization.txt"
  done
}

function get_largest_tables() {
  print_section "Get Largest Tables"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTIONS} "${SQL_LARGEST_TABLES}" >"${OUTPUT_DIR}/${db}_largest_tables.txt"
  done
}

function get_vacuum_stats() {
  print_section "Get Vacuum Stats"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTIONS} "${SQL_VACUUM_STATS}" >"${OUTPUT_DIR}/${db}_vacuum_stats.txt"
  done
}

function get_transaction_wraparound() {
  print_section "Get Transaction Wraparound"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTIONS} "${SQL_TRANSACTION_WRAPAROUND}" >"${OUTPUT_DIR}/${db}_transaction_wraparound.txt"
  done
}

function get_permission_mask() {
  print_section "Get Permission Mask"
  find "${PGDATA}" -maxdepth 1 -type f -perm -o=rwx >"${OUTPUT_DIR}/permission_mask.txt"
}

function get_config_files() {
  print_section "Get Config Files"
  find ${PGDATA} -maxdepth 1 -type f -name "*.conf" | xargs -I {} cp {} "${OUTPUT_DIR}/"
}

SQL_GRANTS="
      SELECT grantee AS user, CONCAT(table_schema, '.', table_name) AS table,
         CASE
            WHEN COUNT(privilege_type) = 7 THEN 'ALL'
            ELSE ARRAY_TO_STRING(ARRAY_AGG(privilege_type), ', ')
         END AS grants
      FROM information_schema.role_table_grants where grantee not in ('PUBLIC', 'postgres', 'pg_read_all_stats')
      GROUP BY table_name, table_schema, grantee;
"

SQL_ROLE_ATTRIBUTES="
  SELECT r.rolname, r.rolsuper, r.rolinherit,
  r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
  r.rolconnlimit, r.rolvaliduntil
  , r.rolreplication
  , r.rolbypassrls
  FROM pg_catalog.pg_roles r
  WHERE r.rolname not like 'pg_%'
  ORDER BY 1;
"

SQL_NOT_VACUUMED="
  SELECT schemaname,
  relname,
  now() - last_autovacuum AS "noautovac",
  now() - last_vacuum AS "novac",
  n_tup_upd,
  n_tup_del,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'
  ||relname)),
  autovacuum_count,
  last_autovacuum,
  vacuum_count,
  last_vacuum
  FROM pg_stat_user_tables
  WHERE (now() - last_autovacuum > '7 days'::interval OR now() - last_vacuum >'7 days'::interval )
  OR (last_autovacuum IS NULL AND last_vacuum IS NULL )
  ORDER BY novac DESC;

"

SQL_UNUSED_INDEXES="
  SELECT 
    relname AS table, 
    indexrelname AS index, 
    pg_size_pretty(pg_relation_size(indexrelid)) AS size
  FROM 
    pg_stat_user_indexes
  WHERE 
    idx_scan = 0
  ORDER BY pg_relation_size(indexrelid) DESC;
"

SQL_INDEX_UTILIZATION="
  SELECT
    schemaname, 
    relname, 
    indexrelname, 
    idx_scan, 
    idx_tup_fetch,
    idx_tup_read
  FROM 
    pg_stat_user_indexes
  ORDER BY 4 DESC,1,2,3;
"

SQL_VACUUM_STATS="
  WITH table_opts AS (
      SELECT
        pg_class.oid, relname, nspname, array_to_string(reloptions, '') AS relopts
      FROM
         pg_class INNER JOIN pg_namespace ns ON relnamespace = ns.oid
    ), vacuum_settings AS (
      SELECT
        oid, relname, nspname,
        CASE
          WHEN relopts LIKE '%autovacuum_vacuum_threshold%'
            THEN substring(relopts, '.*autovacuum_vacuum_threshold=([0-9.]+).*')::integer
            ELSE current_setting('autovacuum_vacuum_threshold')::integer
          END AS autovacuum_vacuum_threshold,
        CASE
          WHEN relopts LIKE '%autovacuum_vacuum_scale_factor%'
            THEN substring(relopts, '.*autovacuum_vacuum_scale_factor=([0-9.]+).*')::real
            ELSE current_setting('autovacuum_vacuum_scale_factor')::real
          END AS autovacuum_vacuum_scale_factor
      FROM
        table_opts
    )
    SELECT
      vacuum_settings.nspname AS schema,
      vacuum_settings.relname AS table,
      to_char(psut.last_vacuum, 'YYYY-MM-DD HH24:MI') AS last_vacuum,
      to_char(psut.last_autovacuum, 'YYYY-MM-DD HH24:MI') AS last_autovacuum,
      to_char(pg_class.reltuples, '9G999G999G999') AS rowcount,
      to_char(psut.n_dead_tup, '9G999G999G999') AS dead_rowcount,
      to_char(autovacuum_vacuum_threshold
           + (autovacuum_vacuum_scale_factor::numeric * pg_class.reltuples), '9G999G999G999') AS autovacuum_threshold,
      CASE
        WHEN autovacuum_vacuum_threshold + (autovacuum_vacuum_scale_factor::numeric * pg_class.reltuples) < psut.n_dead_tup
        THEN 'yes'
      END AS expect_autovacuum
    FROM
      pg_stat_user_tables psut INNER JOIN pg_class ON psut.relid = pg_class.oid
        INNER JOIN vacuum_settings ON pg_class.oid = vacuum_settings.oid
    ORDER BY 1;
"

SQL_TRANSACTION_WRAPAROUND="
  WITH max_age AS (
    SELECT 2000000000 as max_old_xid
      , setting AS autovacuum_freeze_max_age
    FROM 
      pg_catalog.pg_settings
    WHERE 
      name = 'autovacuum_freeze_max_age' 
  ), 
  per_database_stats AS (
    SELECT datname
      , m.max_old_xid::int
      , m.autovacuum_freeze_max_age::int
      , age(d.datfrozenxid) AS oldest_current_xid
    FROM 
      pg_catalog.pg_database d
    JOIN 
      max_age m ON (true)
    WHERE d.datallowconn
  )
  SELECT max(oldest_current_xid) AS oldest_current_xid
      , max(ROUND(100*(oldest_current_xid/max_old_xid::float))) AS percent_towards_wraparound
      , max(ROUND(100*(oldest_current_xid/autovacuum_freeze_max_age::float))) AS percent_towards_emergency_autovac
  FROM per_database_stats;
"

SQL_DUPLICATE_INDEXES="
  SELECT 
    indrelid::regclass AS table, 
    indkey AS column_numbers,
    array_agg(indexrelid::regclass) AS indexes, 
    pg_catalog.pg_get_expr(indpred, indrelid, true) AS expression
  FROM 
    pg_index
  GROUP BY 
    indrelid, 
    indkey, 
    pg_catalog.pg_get_expr(indpred,indrelid, true)
  HAVING count(*) > 1;
"

SQL_LARGEST_TABLE="
  SELECT 
    QUOTE_IDENT(TABLE_SCHEMA)||'.'||QUOTE_IDENT(table_name) as table_name,
    pg_relation_size(QUOTE_IDENT(TABLE_SCHEMA)||'.'|| QUOTE_IDENT(table_name)) as size,
    pg_total_relation_size(QUOTE_IDENT(TABLE_SCHEMA)||'.'|| QUOTE_IDENT(table_name)) as total_size,
    pg_size_pretty(pg_relation_size(QUOTE_IDENT(TABLE_SCHEMA)||'.'||QUOTE_IDENT(table_name))) as pretty_relation_size,
    pg_size_pretty(pg_total_relation_size(QUOTE_IDENT(TABLE_SCHEMA)||'.'||QUOTE_IDENT(table_name))) as pretty_total_relation_size 
  FROM 
    information_schema.tables 
  WHERE 
    QUOTE_IDENT(TABLE_SCHEMA) NOT IN ('snapshots') 
  ORDER BY 
    size DESC LIMIT 10;
"

function print_section_console() {
  local width=80
  local sep="-"
  local title=" $1 "
  local title_length=${#title}
  local total_padding=$((width - title_length))
  local padding_left=$((total_padding / 2))
  local padding_right=$((total_padding - padding_left))
  printf "\n\n%*s" $padding_left | tr " " "$sep"
  printf "%s" "$title"
  printf "%*s\n" $padding_right | tr " " "$sep"
}

function print_section_report() {
  local title=$1
  echo "=== $title" >>"${OUTPUT_REPORT}"
}

function print_section() {
  print_section_console "$1"
  print_section_report "$1"
}

function print_subsection_report() {
  local title=$1
  echo "==== $title" >>"${OUTPUT_REPORT}"
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
    info "PGPORT: ${PGPORT}"
    info "PGHOST: ${PGHOST}"
  fi
  shift $((OPTIND - 1))
}

function log_cleanup() {
  sed -i 's/\x1b\[[0-9;]*m//g' "${LOG_FILE}"
  sed -i 's/\x1b(B//g' "${LOG_FILE}"
}

function main() {
  init
  parse_params
  # check_service
  get_service_status
  get_data_directory
  check_pgdata
  check_pgdata_permissions
  get_databases
  check_user
  get_cpu
  get_memory
  get_disk
  disk_alert
  get_version
  get_all_settings
  get_role_attributes
  get_user_grants
  get_not_vacuumed
  get_unused_indexes
  get_index_utiliation
  get_vacuum_stats
  get_transaction_wraparound
  get_permission_mask
  get_config_files
  log_cleanup
}

main
