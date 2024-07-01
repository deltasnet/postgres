
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

SQL_LARGEST_TABLES="
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

REPLICATION_USER="
  SELECT rolname 
  FROM pg_roles
  WHERE rolreplication = true AND rolname != 'postgres';  
"

PRIVILEGES="
  SELECT p.proname, p.proargtypes, a.rolname 
  FROM pg_proc p 
  JOIN pg_authid a ON p.proowner = a.oid  
  WHERE a.rolsuper = 't' AND a.rolname != 'postgres';
"
