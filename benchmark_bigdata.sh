#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Benchmark Auth Logs: PG vs ES
# -----------------------------
# Requisitos: bash, curl, docker, psql no container "postgres"; (opcional) jq.
# Uso básico:
#   chmod +x benchmark_bigdata.sh
#   # Período completo (todos os índices):
#   ES_INDEX="ssh-failed-attempts-*" USE_RANGE=false ./benchmark_bigdata.sh
#   # Um único dia:
#   ES_INDEX="ssh-failed-attempts-2025.11.11" USE_RANGE=true D1=2025-11-11T00:00:00Z D2=2025-11-12T00:00:00Z ./benchmark_bigdata.sh
#
# Variáveis customizáveis (export antes de rodar ou edite aqui):
ES_HOST="${ES_HOST:-http://localhost:9200}"
PG_CONTAINER="${PG_CONTAINER:-postgres}"
PGUSER="${PGUSER:-loguser}"
PGDB="${PGDB:-logdb}"

# Padrão: todos os índices (período completo)
ES_INDEX="${ES_INDEX:-ssh-failed-attempts-*}"
# Controle de janela temporal (true = filtrar por D1/D2; false = período completo sem range)
USE_RANGE="${USE_RANGE:-false}"
# Janela do dia (UTC) — usada apenas se USE_RANGE=true
D1="${D1:-}"
D2="${D2:-}"

# ---------------------------
# Checagens de dependências
# ---------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "Faltando comando: $1"; exit 1; }; }
need curl
need docker

has_jq=0
if command -v jq >/dev/null 2>&1; then has_jq=1; fi

# ---------------------------
# Helpers
# ---------------------------
say() { printf "\n\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\n\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err() { printf "\n\033[1;31m[ERR]\033[0m  %s\n" "$*"; }

avg() { # recebe lista de números (float/inteiros) via args
  awk 'BEGIN{sum=0; n=0} {sum+= $1; n+=1} END{ if(n>0) printf("%.3f\n", sum/n); else print "0"}' <<<"$(printf "%s\n" "$@")"
}

# Executa consulta no Postgres e retorna tempo em ms
pg_time_ms() {
  local sql="$1"
  docker exec -i "$PG_CONTAINER" psql -U "$PGUSER" -d "$PGDB" -v ON_ERROR_STOP=1 -X -q <<SQL | sed -n 's/.*Execution Time: \([0-9.]\+\) ms.*/\1/p' | tail -n1
\\timing off
EXPLAIN (ANALYZE, BUFFERS, TIMING)
${sql};
SQL
}

# Executa consulta no ES e retorna "took" em ms
es_took_ms() {
  local json="$1"
  if [ "$has_jq" -eq 1 ]; then
    curl -sS -H 'Content-Type: application/json' "${ES_HOST}/${ES_INDEX}/_search" -d "$json" | jq -r '.took // empty'
  else
    curl -sS -H 'Content-Type: application/json' "${ES_HOST}/${ES_INDEX}/_search?filter_path=took" -d "$json" \
      | sed -n 's/{"took":\([0-9]\+\)}/\1/p'
  fi
}

# Snapshot de memória/CPU dos contêineres (um print rápido)
snapshot_stats() {
  say "docker stats (snapshot):"
  docker stats --no-stream --format '  {{.Name}}  |  MEM {{.MemUsage}}  |  CPU {{.CPUPerc}}' postgres elasticsearch 2>/dev/null || true
}

# Tamanho de volumes (se existirem com esses nomes)
volume_size() {
  local vol="$1"
  if docker volume inspect "$vol" >/dev/null 2>&1; then
    local bytes
    bytes=$(docker run --rm -v "${vol}:/d" busybox sh -c 'du -sb /d | cut -f1' || echo 0)
    if command -v numfmt >/dev/null 2>&1; then
      numfmt --to=iec --suffix=B "$bytes"
    else
      echo "${bytes}B"
    fi
  else
    echo "N/A"
  fi
}

# ---------------------------
# Janela temporal opcional
# ---------------------------
if [ "$USE_RANGE" = "true" ]; then
  if [ -z "$D1" ] || [ -z "$D2" ]; then
    warn "USE_RANGE=true, mas D1/D2 não definidos. Defina-os manualmente (UTC) ou rode USE_RANGE=false para período completo."
    # fallback: usa hoje (UTC) como exemplo
    D1="${D1:-$(date -u -d 'today 00:00:00' +%Y-%m-%dT%H:%M:%SZ)}"
    D2="${D2:-$(date -u -d 'tomorrow 00:00:00' +%Y-%m-%dT%H:%M:%SZ)}"
  fi
  say "Modo janela: D1=$D1  D2=$D2"
  ES_FILTER_TIME='{ "range": { "@timestamp": { "gte": "'"$D1"'", "lt": "'"$D2"'" } } },'
  SQL_TIME_AL="AND al.timestamp >= '${D1}' AND al.timestamp < '${D2}'"
  SQL_TIME="AND timestamp >= '${D1}' AND timestamp < '${D2}'"
  SQL_TIME_MV="AND timestamp >= '${D1}' AND timestamp < '${D2}'"
else
  say "Modo período completo (sem filtro de data)"
  ES_FILTER_TIME=""
  SQL_TIME_AL=""
  SQL_TIME=""
  SQL_TIME_MV=""
fi

# ---------------------------
# Casos de teste
# ---------------------------
# A) Top 10 IPs do Brasil (período escolhido)
sql_A="SELECT al.source_ip, COUNT(*) AS attempts
FROM auth_logs al
JOIN geoip_blocks gb ON al.source_ip <<= gb.network
JOIN geoip_locations gl ON gb.geoname_id = gl.geoname_id
WHERE gl.country_iso_code = 'BR'
  ${SQL_TIME_AL}
GROUP BY al.source_ip
ORDER BY attempts DESC
LIMIT 10"

es_A=$(cat <<JSON
{
  "size": 0,
  "query": {
    "bool": { "filter": [
      ${ES_FILTER_TIME}
      { "term":  { "geoip.geo.country_iso_code.keyword": "BR" } }
    ]}
  },
  "runtime_mappings": {
    "ip_rt": {
      "type": "ip",
      "script": "def v = params._source.source_ip; if (v == null) { v = params._source.geoip?.ip; } if (v != null) emit(v);"
    }
  },
  "aggs": {
    "top_ips": {
      "terms": { "field": "ip_rt", "size": 10, "order": { "_count": "desc" } }
    }
  }
}
JSON
)

# B) Top 10 usuários por tentativas (falhas)
sql_B="SELECT username,
       COUNT(*)       AS attempts,
       MIN(timestamp) AS first_seen,
       MAX(timestamp) AS last_seen
FROM auth_logs
WHERE event_type = 'failed_password'
  ${SQL_TIME}
GROUP BY username
ORDER BY attempts DESC
LIMIT 10"

es_B=$(cat <<JSON
{
  "size": 0,
  "query": {
    "bool": { "filter": [
      ${ES_FILTER_TIME}
      { "terms": { "tags": ["failed_ssh"] } }
    ]}
  },
  "aggs": {
    "by_user": {
      "terms": { "field": "username.keyword", "size": 10, "order": { "_count": "desc" } },
      "aggs": {
        "first_seen": { "min": { "field": "@timestamp" } },
        "last_seen":  { "max": { "field": "@timestamp" } }
      }
    }
  }
}
JSON
)

# C) Busca de texto (contagem de linhas com "Failed password")
sql_C="SELECT COUNT(*)
FROM auth_logs
WHERE log_message ILIKE '%Failed password%'
  ${SQL_TIME}"

es_C=$(cat <<JSON
{
  "size": 0,
  "query": {
    "bool": {
      "must":    [{ "match_phrase": { "log_message": "Failed password" } }],
      "filter":  [ ${ES_FILTER_TIME} { "match_all": {} } ]
    }
  }
}
JSON
)

# D) Top países por falhas (agregação cross-dados)
sql_D="SELECT country_name, COUNT(*) AS attempts
FROM auth_logs_with_geoip
WHERE event_type = 'failed_password'
  ${SQL_TIME_MV}
GROUP BY country_name
ORDER BY attempts DESC
LIMIT 10"

es_D=$(cat <<JSON
{
  "size": 0,
  "query": { "bool": { "filter": [ ${ES_FILTER_TIME} { "terms": { "tags": ["failed_ssh"] } } ] } },
  "aggs": {
    "by_country": {
      "terms": { "field": "geoip.geo.country_name.keyword", "size": 10 }
    }
  }
}
JSON
)

# ---------------------------
# Runner genérico (3x por caso)
# ---------------------------
run_case() {
  local name="$1"
  local sql="$2"
  local es="$3"

  say "Caso ${name} — PostgreSQL (3x)"
  local pg_times=()
  for i in 1 2 3; do
    t="$(pg_time_ms "$sql" || echo "")"
    if [ -z "$t" ]; then err "PG sem tempo capturado (consulta/parse falhou?)"; exit 1; fi
    echo "  PG run #$i: ${t} ms"
    pg_times+=("$t")
  done
  local pg_avg; pg_avg=$(avg "${pg_times[@]}")
  echo "  PG média: ${pg_avg} ms"

  say "Caso ${name} — Elasticsearch (3x)  [ES_INDEX=${ES_INDEX}]"
  local es_times=()
  for i in 1 2 3; do
    t="$(es_took_ms "$es" || echo "")"
    if [ -z "$t" ]; then err "ES sem took (consulta/parse falhou?)"; exit 1; fi
    echo "  ES run #$i: ${t} ms"
    es_times+=("$t")
  done
  local es_avg; es_avg=$(avg "${es_times[@]}")
  echo "  ES média: ${es_avg} ms"

  snapshot_stats

  # CSV inline
  printf "CSV;%s;%s;%s\n" "$name" "$pg_avg" "$es_avg" >> benchmark_results.csv
}

# ---------------------------
# Execução
# ---------------------------
: > benchmark_results.csv
echo "CSV_CASE;PG_ms_avg;ES_ms_avg" > benchmark_results.csv

say "Iniciando benchmarks com ES_INDEX=${ES_INDEX}  USE_RANGE=${USE_RANGE}"
[ "$USE_RANGE" = "true" ] && say "Janela ativa: D1=$D1  D2=$D2"

run_case "A_TopIPs_BR"            "$sql_A" "$es_A"
run_case "B_TopUsers_failed"      "$sql_B" "$es_B"
run_case "C_TextSearch_failedpwd" "$sql_C" "$es_C"
run_case "D_TopCountries_failed"  "$sql_D" "$es_D"

say "Resumo (CSV):"
column -s';' -t benchmark_results.csv || cat benchmark_results.csv

# Tamanhos de volumes (se existirem com esses nomes)
PG_VOL="postgres_data"
ES_VOL="elasticsearch_data"
say "Tamanho dos volumes:"
echo "  ${PG_VOL}: $(volume_size "$PG_VOL")"
echo "  ${ES_VOL}: $(volume_size "$ES_VOL")"

say "Feito. Resultados em ./benchmark_results.csv"
