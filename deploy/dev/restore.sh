#!/bin/sh
# Restores the kernel database into an empty stack (README.md §Backups, STD-GLB-009 1.10.0 rule 9,
# STD-GLB-002 §Restore Evidence).
#
#   ./restore.sh /mnt/imam-storage/scnehaux-backups/identity-kernel/globals-2026-10-20.sql \
#                /mnt/imam-storage/scnehaux-backups/identity-kernel/keycloak-2026-10-20.dump
#   docker compose up -d --build --wait
#
# 1. Starts postgres alone and waits until it accepts TCP connections, which the image's first-start
#    initialisation does not.
# 2. Refuses a cluster whose database keycloak holds anything. The image creates keycloak empty on a
#    new volume (POSTGRES_DB), so an empty one is what a new volume looks like, and it is dropped for
#    the restore to create it again. Replacing a database that holds a realm is a decision an operator
#    makes by deleting the volume (README.md §Never do), never a side effect.
# 3. Applies the roles from the pg_dumpall file. A database dump holds no roles, and every owner and
#    grantee in it must exist before it is restored. The one error allowed is the bootstrap
#    superuser's "role already exists", which PostgreSQL documents as harmless; any other stops here.
#    The roles file also sets keycloak's password hash to the one backed up, so .env goes back first.
# 4. Restores the database whole with pg_restore --create --exit-on-error: the first error stops it,
#    rather than a count of errors at the end.
#
# The realm signing keystore is not in the backup and is not restored. The kernel loads it from
# keys/signing as before, and the restored realm names the same provider and kid, so the key set is
# the one published before the loss (TDD-identity-kernel-002 §Compromise and Recovery). On a host that
# lost keys/ too, a restore is a new ceremony and a new kid: docs/runbooks/database-restore.md.
# deploy-dev runs this script in its restore drill (scripts/dev-restore-drill.sh).
set -eu

globals="${1:?usage: restore.sh <globals.sql> <keycloak.dump>}"
dump="${2:?usage: restore.sh <globals.sql> <keycloak.dump>}"
database=keycloak
for file in "$globals" "$dump"; do
	[ -r "$file" ] || { echo "cannot read $file" >&2; exit 1; }
done
globals="$(cd "$(dirname "$globals")" && pwd)/$(basename "$globals")"
dump="$(cd "$(dirname "$dump")" && pwd)/$(basename "$dump")"
cd "$(dirname "$0")"

psql() { docker compose exec -T postgres psql -X -qtA -U keycloak "$@"; }

echo "[1/4] postgres"
docker compose up -d postgres
i=0
until docker compose exec -T postgres pg_isready -q -h 127.0.0.1 -U keycloak -d postgres; do
	i=$((i + 1))
	[ "$i" -lt 60 ] || { echo "postgres did not accept connections within 60s" >&2; exit 1; }
	sleep 1
done

echo "[2/4] an empty cluster"
held="$(psql -d postgres -c "SELECT count(*) FROM pg_database WHERE datname = '$database'")"
if [ "$held" != "0" ]; then
	relations="$(psql -d "$database" -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'")"
	if [ "$relations" != "0" ]; then
		echo "refusing: this cluster's $database holds $relations relations; restore into an empty volume" >&2
		exit 1
	fi
	psql -d postgres -c "DROP DATABASE $database" > /dev/null
fi

echo "[3/4] roles"
errors="$(docker compose exec -T -e PGOPTIONS='-c client_min_messages=warning' postgres \
	psql -X -q -U keycloak -d postgres < "$globals" 2>&1 >/dev/null)" || true
unexpected="$(printf '%s\n' "$errors" | grep -E 'ERROR|FATAL|PANIC' | grep -v 'role "keycloak" already exists' || true)"
if [ -n "$unexpected" ]; then
	printf '%s\n' "$unexpected" >&2
	exit 1
fi

echo "[4/4] $database"
docker compose exec -T postgres pg_restore -U keycloak -d postgres --create --exit-on-error < "$dump"

echo "restored $database; next: docker compose up -d --build --wait"
