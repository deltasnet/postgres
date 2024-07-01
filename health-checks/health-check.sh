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

function check_user() {
  print_section "Check User"

  if [ "$(whoami)" != "postgres" ]; then
    err "Please run as postgres user"
  else
    ok "Running as postgres user"
  fi
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
PGOPTS="${PGOPTS:-"--host ${PGHOST} --port ${PGPORT} --user ${PGUSER}"}"
PGARGS="${PGARGS:-"-At -c"}"
PGARGS_READABLE="${PGARGS_READABLE:-"-c"}"

USER=postgres
DBS=""

OUTPUT_REPORT="${OUTPUT_DIR}/health-check-report.adoc"

#####
#
# Hardware Resources
#
#####
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

#####
#
# Service
#
#####
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

function check_connection() {
  print_section "Check Connection"
  if ! pg_isready ${PGOPTS} >/dev/null; then
    err "Cannot connect to the database."
  fi
  ok "Connected to the database."
}

function check_pgdata() {
  print_section "Check PGDATA"
  get_data_directory
  check_pgdata_owner
  check_pgdata_permissions
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

function get_databases() {
  print_section "List Databases"
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

function check_logging() {
  print_section "Logging"
  check_log_destination
  check_log_collector
  check_log_directory
  check_log_file_mode
  check_log_truncate
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

function check_log_collector() {
  local log_collector
  log_collector=$(psql ${PGOPTS} ${PGARGS} "SHOW logging_collector;")
  if [[ -z "${log_collector// /}" ]]; then
    warn "Log collector not set"
  else
    ok "Log collector is set to '${log_collector}'."
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

function get_role_attributes() {
  print_section "Get Role Attributes"
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

function get_not_vacuumed() {
  print_section "Get Not Vacuumed for 7 days"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS_READABLE} "${SQL_NOT_VACUUMED}" >"${OUTPUT_DIR}/${db}/not_vacuumed.txt"
    info "Tables not vacuumed for 7 days in database ${db} saved to ${OUTPUT_DIR}/${db}/not_vacuumed.txt."
  done
}

function get_unused_indexes() {
  print_section "Get Unused Indexes"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_UNUSED_INDEXES}" >"${OUTPUT_DIR}/${db}/unused_indexes.txt"
    info "Unused indexes in database ${db} saved to ${OUTPUT_DIR}/${db}/unused_indexes.txt."
  done
}

function get_duplicate_indexes() {
  print_section "Get Duplicate Indexes"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_DUPLICATE_INDEXES}" >"${OUTPUT_DIR}/${db}/duplicate_indexes.txt"
    info "Duplicate indexes in database ${db} saved to ${OUTPUT_DIR}/${db}/duplicate_indexes.txt."
  done
}

function get_index_utiliation() {
  print_section "Get Index Utilization"
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

function get_vacuum_stats() {
  print_section "Get Vacuum Stats"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_VACUUM_STATS}" >"${OUTPUT_DIR}/${db}/vacuum_stats.txt"
    info "Vacuum stats in database ${db} saved to ${OUTPUT_DIR}/${db}/vacuum_stats.txt."
  done
}

function get_transaction_wraparound() {
  print_section "Get Transaction Wraparound"
  for db in ${DBS}; do
    psql -d "$db" ${PGOPTS} ${PGARGS} "${SQL_TRANSACTION_WRAPAROUND}" >"${OUTPUT_DIR}/${db}/transaction_wraparound.txt"
    info "Transaction wraparound in database ${db} saved to ${OUTPUT_DIR}/${db}/transaction_wraparound.txt."
  done
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

function get_config_files() {
  print_section "Get Config Files"
  find "${PGDATA}" -maxdepth 1 -type f -name "*.conf" -print0 | xargs -0 -I {} cp {} "${OUTPUT_DIR}/"
  if [ $? -eq 0 ]; then
    info "Config files copied to ${OUTPUT_DIR}."
  else
    warn "Error copying config files."
  fi
}

function get_replication_info() {
  print_section "Get Replication Info"
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

function get_replication_stats_primary() {
  print_subsection "Replication Stats"
  psql ${PGOPTS} ${PGARGS_READABLE} "${REPLICATION_STATS_PRIMARY}" >"${OUTPUT_DIR}/replication_stats.txt"
  info "Replication stats saved to ${OUTPUT_DIR}/replication_stats.txt."
}

function get_replication_stats_standby() {
  print_subsection "Replication Stats"
  psql ${PGOPTS} ${PGARGS_READABLE} "${REPLICATION_STATS_STANDBY}" >"${OUTPUT_DIR}/replication_stats.txt"
  info "Replication stats saved to ${OUTPUT_DIR}/replication_stats.txt."
}

function get_replication_slots() {
  print_subsection "Replication Slots"
  psql ${PGOPTS} ${PGARGS} "${REPLICATION_SLOTS}" >"${OUTPUT_DIR}/replication_slots.txt"
  info "Replication slots in database ${db} saved to ${OUTPUT_DIR}/replication_slots.txt."
}

function get_replication_lag() {
  print_subsection "Replication Lag"
  psql ${PGOPTS} ${PGARGS} "${REPLICATION_LAG}" >"${OUTPUT_DIR}/replication_lag.txt"
  info "Replication lag saved to ${OUTPUT_DIR}/replication_lag.txt."
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
  SELECT CONCAT(schemaname,
  relname),
  now() - last_autovacuum AS noautovac,
  now() - last_vacuum AS novac,
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

USER_PERMISSIONS="
    WITH roles AS (
        SELECT
            r.oid,
            r.rolname AS username,
            ARRAY(
                SELECT b.rolname
                FROM pg_catalog.pg_auth_members m
                JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
                WHERE m.member = r.oid
            ) AS roles,
            CASE
                WHEN r.rolsuper THEN 'superuser'
                WHEN r.rolcreaterole THEN 'create role'
                WHEN r.rolcreatedb THEN 'create database'
                ELSE 'normal'
            END AS privilege,
            r.rolcreatedb AS can_create_db,
            r.rolcanlogin AS can_login,
            r.rolreplication AS can_replicate,
            r.rolconnlimit AS connection_limit,
            r.rolvaliduntil AS password_expiry,
            r.rolconfig AS config,
            r.rolvaliduntil::date AS expiry_date,
            r.rolpassword IS NOT NULL AS has_password
        FROM
            pg_catalog.pg_roles r
        WHERE
            r.rolname NOT LIKE 'pg_%'
    ),
    table_grants AS (
        SELECT
            grantee,
            schemaname,
            tablename,
            array_agg(privilege_type ORDER BY privilege_type) AS privileges
        FROM
            (
                SELECT
                    r.rolname AS grantee,
                    n.nspname AS schemaname,
                    c.relname AS tablename,
                    CASE
                        WHEN has_table_privilege(r.oid, c.oid, 'SELECT') THEN 'SELECT'
                        WHEN has_table_privilege(r.oid, c.oid, 'INSERT') THEN 'INSERT'
                        WHEN has_table_privilege(r.oid, c.oid, 'UPDATE') THEN 'UPDATE'
                        WHEN has_table_privilege(r.oid, c.oid, 'DELETE') THEN 'DELETE'
                        WHEN has_table_privilege(r.oid, c.oid, 'TRUNCATE') THEN 'TRUNCATE'
                        WHEN has_table_privilege(r.oid, c.oid, 'REFERENCES') THEN 'REFERENCES'
                        WHEN has_table_privilege(r.oid, c.oid, 'TRIGGER') THEN 'TRIGGER'
                    END AS privilege_type
                FROM
                    pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    CROSS JOIN pg_catalog.pg_roles r
                WHERE
                    c.relkind IN ('r', 'v', 'm', 'f', 'p')
                    AND r.rolname NOT LIKE 'pg_%'
                    AND n.nspname NOT LIKE 'pg_%'
                    AND n.nspname != 'information_schema'
            ) AS subquery
        WHERE
            privilege_type IS NOT NULL
        GROUP BY
            grantee, schemaname, tablename
    ),
    grants_agg AS (
        SELECT
            grantee,
            string_agg(
                CASE
                    WHEN schemaname = 'public'
                    THEN tablename
                    ELSE schemaname || '.' || tablename
                END ||
                ': ' || array_to_string(privileges, ', '),
                E'\n'
            ) AS table_grants
        FROM
            table_grants
        WHERE
            schemaname NOT LIKE 'pg_%' OR schemaname != 'information_schema'
        GROUP BY
            grantee
    ),
    database_grants AS (
        SELECT
            r.rolname AS grantee,
            string_agg(DISTINCT 'Database ' || d.datname || ': ' ||
                CASE
                    WHEN has_database_privilege(r.oid, d.oid, 'CREATE') THEN 'CREATE'
                    WHEN has_database_privilege(r.oid, d.oid, 'CONNECT') THEN 'CONNECT'
                    WHEN has_database_privilege(r.oid, d.oid, 'TEMPORARY') THEN 'TEMPORARY'
                END,
                E'\n'
            ) AS db_grants
        FROM
            pg_catalog.pg_database d
            CROSS JOIN pg_catalog.pg_roles r
        WHERE
            r.rolname NOT LIKE 'pg_%'
            AND has_database_privilege(r.oid, d.oid, 'CREATE,CONNECT,TEMPORARY')
        GROUP BY
            r.rolname
    )
    SELECT
        r.username,
        r.roles,
        r.privilege,
        r.can_create_db,
        r.can_login,
        r.can_replicate,
        r.connection_limit,
        r.password_expiry,
        r.config,
        r.expiry_date,
        r.has_password,
        COALESCE(g.table_grants, 'No specific table grants') AS table_grants,
        COALESCE(d.db_grants, 'No specific database grants') AS database_grants,
        pg_catalog.shobj_description(r.oid, 'pg_authid') AS description
    FROM
        roles r
    LEFT JOIN
        grants_agg g ON r.username = g.grantee
    LEFT JOIN
        database_grants d ON r.username = d.grantee
    ORDER BY
        r.username;    
"

IS_SLAVE="
  SELECT pg_is_in_recovery();
"

REPLICATION_LAG="
  SELECT CASE
    WHEN pg_last_wal_receive_lsn () = pg_last_wal_replay_lsn ()
      THEN 0
    ELSE
      extract ( epoch from now () - pg_last_xact_replay_timestamp () )
    END 
  AS log_delay ;    
"

REPLICATION_STATS_PRIMARY="
  SELECT
  *
  FROM
  pg_stat_replication;
"
REPLICATION_STATS_STANDBY="
  SELECT *
  FROM pg_stat_wal_receiver;
"

REPLICATION_SLOTS="
  SELECT
  *
  FROM
    pg_replication_slots;
"

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
  check_user
  check_resources
  check_service
  check_connection
  check_pgdata
  check_pgdata
  check_pgdata_permissions
  get_permission_mask
  check_logging
  get_databases
  get_version
  get_all_settings
  get_role_attributes
  get_user_grants
  get_user_permissions
  get_not_vacuumed
  get_unused_indexes
  get_index_utiliation
  get_vacuum_stats
  get_transaction_wraparound
  get_config_files
  get_replication_info
  log_cleanup
}

main
