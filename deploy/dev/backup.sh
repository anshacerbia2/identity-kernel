#!/bin/sh
# The kernel database's backup (README.md §Backups, STD-GLB-009 1.10.0 rule 9): the cluster's roles and
# the database keycloak, read from the running postgres container into a directory outside the Docker
# volume.
#
#   ./backup.sh /mnt/dev-storage/scnehaux-backups/identity-kernel
#
# Writes one set: globals-<date>.sql (pg_dumpall --globals-only) and keycloak-<date>.dump
# (pg_dump --format=custom), <date> the UTC date. Prints the two paths, roles first: restore.sh takes
# them in that order.
#
#   - Each file is written as <name>.partial and renamed only when its command succeeded, so a failed
#     run never leaves a file that looks like a backup.
#   - The dump is verified before it is renamed: pg_restore --list reads its whole table of contents,
#     and the roles file must create the role keycloak. A dump that does not read back is not a backup.
#   - Then, and only then, the newest 14 complete sets are kept and older ones deleted. A set is
#     complete when both its files exist. Retention is by count, never by age: a failed or silent
#     backup deletes nothing, and a week of failures still leaves 14 good sets (rule 9). Leftover
#     .partial files older than the oldest kept set go too.
#   - Both files hold role password hashes, so they are written with umask 077, readable by their owner
#     alone.
#   - The realm signing keystore and its password are never copied: they are files in keys/signing and
#     keys/vault, outside the database, and this script reads the database alone. A lost keystore is
#     replaced by a new ceremony and a new kid, never restored (ADR-IAM-002 §5.3). The database holds
#     only the provider's configuration, whose passwords are vault references.
#
# pg_dump "makes consistent backups even if the database is being used concurrently", so the kernel
# keeps running. It connects over the container's local socket as the role keycloak, which the image
# trusts there: no password is typed or stored here. deploy-dev runs this script in its restore drill
# (scripts/dev-restore-drill.sh).
set -eu

dir="${1:?usage: backup.sh <directory outside the Docker volume>}"
database=keycloak
keep=14

umask 077
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
cd "$(dirname "$0")"

stamp="$(date -u +%F)"
globals="$dir/globals-$stamp.sql"
dump="$dir/$database-$stamp.dump"

docker compose exec -T postgres pg_dumpall -U keycloak --globals-only > "$globals.partial"
docker compose exec -T postgres pg_dump -U keycloak --format=custom "$database" > "$dump.partial"

if ! grep -q '^CREATE ROLE keycloak;' "$globals.partial"; then
	echo "backup: $globals.partial does not create the role keycloak; keeping the previous sets" >&2
	exit 1
fi
if ! docker compose exec -T postgres pg_restore --list < "$dump.partial" > /dev/null; then
	echo "backup: $dump.partial does not read back with pg_restore --list; keeping the previous sets" >&2
	exit 1
fi

mv "$globals.partial" "$globals"
mv "$dump.partial" "$dump"

# The newest $keep complete sets, by date, newest first. A date sorts as text.
complete="$(for f in "$dir"/"$database"-*.dump; do
	[ -e "$f" ] || continue
	date="${f##*/$database-}"
	date="${date%.dump}"
	[ -e "$dir/globals-$date.sql" ] && echo "$date"
done | sort -r)"
oldest_kept="$(printf '%s\n' "$complete" | head -n "$keep" | tail -n 1)"
for date in $(printf '%s\n' "$complete" | tail -n "+$((keep + 1))"); do
	rm -f "$dir/globals-$date.sql" "$dir/$database-$date.dump"
done
# A lone file or a .partial older than every kept set belongs to no set that will ever complete.
for f in "$dir"/globals-*.sql "$dir"/globals-*.sql.partial "$dir"/"$database"-*.dump "$dir"/"$database"-*.dump.partial; do
	[ -e "$f" ] || continue
	date="$(basename "$f" | sed -E 's/^(globals|'"$database"')-([0-9]{4}-[0-9]{2}-[0-9]{2}).*/\2/')"
	[ -n "$oldest_kept" ] && [ "$date" != "$oldest_kept" ] || continue
	if [ "$(printf '%s\n%s\n' "$date" "$oldest_kept" | sort | head -n 1)" = "$date" ]; then
		rm -f "$f"
	fi
done

echo "$globals"
echo "$dump"
