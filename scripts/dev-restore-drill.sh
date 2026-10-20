#!/usr/bin/env bash
# The kernel database's restore drill (STD-GLB-002 §Restore Evidence, STD-GLB-009 1.10.0 rule 9,
# TDD-identity-kernel-002 1.2.0 §Compromise and Recovery, docs/runbooks/database-restore.md).
# deploy-dev runs it last, on the stack it brought up, with the realm applied:
#
#   1. creates a person in the realm, so users and credentials exist to restore, reads the realm
#      through the Admin API and the key set through the proxy, and stops the kernel so nothing writes;
#   2. fingerprints the database: its schema with owners and grants, Keycloak's migration, every
#      table's row count and content checksum, every sequence, and the cluster's roles;
#   3. proves the retention rule: with 15 older sets in place, a backup that fails deletes none of them,
#      and the next one keeps the newest 14 complete sets, its own among them;
#   4. backs up with deploy/dev/backup.sh, the script README.md §Backups gives the operator's cron, and
#      proves the backup holds no signing material: no keystore file, not the keystore's password, and
#      no private key in the signing provider's configuration;
#   5. deletes the database volume with docker compose down --volumes, the loss a backup is for;
#   6. restores into the new, empty volume with deploy/dev/restore.sh, and fingerprints it again before
#      the kernel starts and migrates anything; a second restore.sh over it must refuse, and two probes
#      show the checks are load-bearing: one row removed in a rolled-back transaction changes the
#      fingerprint, and the same dump restored into a cluster without its roles stops;
#   7. starts the stack, runs the realm-apply job, which must find the realm in sync and signing with the
#      keystore's key, and reads again: the same people, the same realm revision, and the same key set,
#      the keystore's kid among it and no key made since;
#   8. writes restore-evidence.json and fails on any difference, on an empty critical table, or on a
#      recovery slower than the 15-minute RTO of PAD-PLT-001 §6.2.
#
# It deletes the database, so it refuses to run outside CI.
#
#   COMPOSE_FILE=compose.yaml:compose.ci.yaml bash scripts/dev-restore-drill.sh <evidence directory>
set -euo pipefail

out="${1:?usage: dev-restore-drill.sh <evidence directory>}"
if [ "${CI:-}" != "true" ]; then
	echo "refusing: the drill deletes the database volume, so it runs in CI only" >&2
	exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
deploy="$root/deploy/dev"
database=keycloak
realm=scnehaux
volume=scnehaux-identity-dev_postgres
rto_seconds=900
# Each must hold rows in the source, or the drill would be comparing empty tables: the realm, its
# people and their credentials, its clients and scopes, and the key provider's configuration.
required=(public.realm public.user_entity public.credential public.client public.client_scope
	public.protocol_mapper public.component public.component_config public.databasechangelog)
upstream="$(grep -v '^[[:space:]]*#' "$root/image/keycloak.ref" | grep -v '^[[:space:]]*$' | head -n 1 | tr -d '[:space:]')"

mkdir -p "$out"
out="$(cd "$out" && pwd)"
# Stands in for storage outside the Docker volume. The workflow never uploads it: the files hold role
# password hashes.
backup="$out/backup"
mkdir -p "$backup"

compose() { (cd "$deploy" && docker compose "$@"); }
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'; }
env_value() { grep "^$1=" "$deploy/.env" | cut -d= -f2-; }
admin_user="$(env_value KC_BOOTSTRAP_ADMIN_USERNAME)"
admin_password="$(env_value KC_BOOTSTRAP_ADMIN_PASSWORD)"
kc() { compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-drill.config; }

wait_postgres() {
	for _ in $(seq 1 60); do
		compose exec -T postgres pg_isready -q -h 127.0.0.1 -U keycloak -d postgres && return 0
		sleep 1
	done
	echo "::error::postgres did not accept connections within 60s"
	return 1
}

fingerprint() {
	compose exec -T postgres psql -X -v ON_ERROR_STOP=1 -qtA -U keycloak -d "$database" \
		< "$root/scripts/restore-fingerprint.sql" | jq -S . > "$out/fingerprint-$1.json"
	compose exec -T postgres pg_dump -U keycloak --schema-only --create --restrict-key=drill "$database" \
		> "$out/schema-$1.sql"
}

# read_kernel <before|after>: the realm as a client of the kernel sees it.
read_kernel() {
	kc config credentials --server http://localhost:8080 --realm master --user "$admin_user" \
		--password "$admin_password" > /dev/null
	local users revision active jwks
	users="$(kc get users -r "$realm" --limit 1000 --fields username | jq -c '[.[].username] | sort')"
	revision="$(kc get "realms/$realm" --fields attributes |
		jq -r '.attributes["scnehaux.definition.revision"] // ""')"
	active="$(kc get keys -r "$realm" --fields active | jq -c '.active')"
	jwks="$(curl -sfk "https://localhost/realms/$realm/protocol/openid-connect/certs" | jq -c '[.keys[].kid] | sort')"
	jq -n -S --argjson users "$users" --arg revision "$revision" --argjson active "$active" --argjson jwks "$jwks" \
		'{users: $users, revision: $revision, active: $active, jwks: $jwks}' > "$out/read-$1.json"
}

# same <name> <file a> <file b>: true when equal; otherwise false, with the diff kept beside the evidence.
same() {
	if diff -u "$2" "$3" > "$out/diff-$1.txt"; then
		rm -f "$out/diff-$1.txt"
		echo true
	else
		echo false
	fi
}
section() { jq -S ".$2" "$out/fingerprint-$1.json" > "$out/$2-$1.json"; }
complete_sets() {
	local f date
	for f in "$backup"/keycloak-*.dump; do
		[ -e "$f" ] || continue
		date="${f##*/keycloak-}"
		date="${date%.dump}"
		[ -e "$backup/globals-$date.sql" ] && echo "$date"
	done | sort
}

started_at="$(date -u +%FT%TZ)"
cd "$deploy"

echo "1. a person in the realm, the realm read, then the kernel stopped"
kc config credentials --server http://localhost:8080 --realm master --user "$admin_user" \
	--password "$admin_password" > /dev/null
principal="$(python3 -c 'import os, time; b = bytearray(os.urandom(16)); ms = int(time.time() * 1000)
b[0:6] = ms.to_bytes(6, "big"); b[6] = (b[6] & 0x0F) | 0x70; b[8] = (b[8] & 0x3F) | 0x80; h = b.hex()
print(f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}")')"
person="drill-$(openssl rand -hex 4)"
kc create users -r "$realm" -s "username=$person" -s enabled=true -s "email=$person@drill.invalid" \
	-s emailVerified=true -s firstName=Drill -s lastName=Person \
	-s "attributes.scnehaux_principal_id=[\"$principal\"]" -s 'attributes.scnehaux_subject_type=["human"]' > /dev/null
kc set-password -r "$realm" --username "$person" --new-password "Drill-$(openssl rand -hex 12)!" > /dev/null
read_kernel before
kid="$(jq -r '.active.PS256' "$out/read-before.json")"
compose stop keycloak caddy

echo "2. fingerprint the source"
fingerprint source

echo "3. retention: 14 complete sets, pruned only after a successful backup"
for day in $(seq -w 1 15); do
	: > "$backup/globals-2020-01-$day.sql"
	: > "$backup/keycloak-2020-01-$day.dump"
done
compose stop postgres
failed_backup_kept_all=false
if sh "$deploy/backup.sh" "$backup" > "$out/backup-failed.txt" 2>&1; then
	echo "::error::backup.sh succeeded with postgres stopped"
elif [ "$(complete_sets | wc -l)" = 15 ] && [ -z "$(complete_sets | grep -v '^2020-01-' || true)" ]; then
	failed_backup_kept_all=true
fi
compose start postgres
wait_postgres

echo "4. back up with deploy/dev/backup.sh"
t="$(now)"
sh "$deploy/backup.sh" "$backup" > "$out/backup-files.txt"
backup_seconds="$(elapsed "$t" "$(now)")"
globals="$(sed -n 1p "$out/backup-files.txt")"
dump="$(sed -n 2p "$out/backup-files.txt")"
dump_bytes="$(stat -c %s "$dump")"
sets="$(complete_sets)"
kept_newest_14=false
if [ "$(printf '%s\n' "$sets" | wc -l)" = 14 ] && printf '%s\n' "$sets" | grep -qx "$(date -u +%F)" &&
	[ "$(printf '%s\n' "$sets" | head -n 1)" = "2020-01-03" ]; then
	kept_newest_14=true
fi
complete_sets > "$out/backup-sets.txt"

# The backup holds no signing material (STD-GLB-009 rule 9, ADR-IAM-002 §5.3).
no_keystore_file=true
if find "$backup" -type f \( -name '*.p12' -o -name '*.pfx' -o -name '*.jks' -o -name '*keystore*' \
	-o -name '*realm-signing*' \) | grep -q .; then
	no_keystore_file=false
fi
password="$(docker run --rm --network none -v "$deploy/keys/vault:/vault:ro" --entrypoint /bin/cat "$upstream" \
	/vault/scnehaux_realm-signing-password)"
no_keystore_password=false
if [ -n "$password" ] && ! compose exec -T postgres pg_restore -f - < "$dump" | grep -qF "$password" &&
	! grep -qF "$password" "$globals"; then
	no_keystore_password=true
fi
unset password
provider_config="$(compose exec -T postgres psql -X -qtA -U keycloak -d "$database" -c \
	"SELECT coalesce(string_agg(cc.name, ',' ORDER BY cc.name), '') FROM component c
	   JOIN component_config cc ON cc.component_id = c.id
	  WHERE c.name = 'realm-signing-ps256' AND c.provider_type = 'org.keycloak.keys.KeyProvider'")"
no_private_key=false
case ",$provider_config," in
*,privateKey,* | *,certificate,* | ,,) ;;
*) no_private_key=true ;;
esac

echo "5. lose the database: docker compose down --volumes"
volume_before="$(docker volume inspect -f '{{.CreatedAt}}' "$volume")"
compose down --volumes
if docker volume inspect "$volume" > /dev/null 2>&1; then
	echo "::error::the database volume survived docker compose down --volumes"
	exit 1
fi

echo "6. restore into an empty volume with deploy/dev/restore.sh"
t0="$(now)"
sh "$deploy/restore.sh" "$globals" "$dump"
restore_seconds="$(elapsed "$t0" "$(now)")"
volume_after="$(docker volume inspect -f '{{.CreatedAt}}' "$volume")"
fingerprint restored

# The comparison is load-bearing: one row removed from the probe table, inside a transaction that rolls
# back, must change that table's count and checksum.
probe_table=public.user_entity
compose exec -T postgres psql -X -v ON_ERROR_STOP=1 -qtA -U keycloak -d "$database" \
	-c "BEGIN" -c "SET LOCAL session_replication_role = replica" \
	-c "DELETE FROM $probe_table WHERE ctid = (SELECT ctid FROM $probe_table LIMIT 1)" \
	-f - -c "ROLLBACK" < "$root/scripts/restore-fingerprint.sql" | jq -S . > "$out/fingerprint-probe.json"
probe_entry() { jq -c --arg t "$probe_table" '.tables[] | select(.table == $t) | [.rows, .checksum]' "$1"; }
one_row_detected=false
if [ "$(probe_entry "$out/fingerprint-probe.json")" != "$(probe_entry "$out/fingerprint-restored.json")" ] &&
	[ "$(jq '.tables' "$out/fingerprint-probe.json")" != "$(jq '.tables' "$out/fingerprint-source.json")" ]; then
	one_row_detected=true
fi
rm -f "$out/fingerprint-probe.json"

# Roles first is load-bearing: the same dump restored into a cluster without them must stop on its
# first owner.
probe_container="restore-drill-probe-$$"
image="$(docker inspect -f '{{.Config.Image}}' "$(compose ps -q postgres)")"
docker run -d --rm --name "$probe_container" --network none -e POSTGRES_PASSWORD="$(openssl rand -hex 16)" \
	"$image" > /dev/null
for _ in $(seq 1 60); do
	docker exec "$probe_container" pg_isready -q -h 127.0.0.1 -U postgres && break
	sleep 1
done
without_roles_refused=false
if docker exec -i "$probe_container" pg_restore -U postgres -d postgres --create --exit-on-error \
	< "$dump" > "$out/restore-without-roles.txt" 2>&1; then
	echo "::error::the dump restored into a cluster without its roles; the roles-first order tests nothing"
else
	grep -qE 'role "[^"]+" does not exist' "$out/restore-without-roles.txt" && without_roles_refused=true
fi
docker rm -f "$probe_container" > /dev/null

refuses_occupied=false
if sh "$deploy/restore.sh" "$globals" "$dump" > "$out/second-restore.txt" 2>&1; then
	echo "::error::a second restore.sh ran over the restored database; it must refuse"
else
	grep -qF "refusing:" "$out/second-restore.txt" && refuses_occupied=true
fi

echo "7. start the stack on the restored database"
t="$(now)"
compose up -d --wait --wait-timeout 300 postgres keycloak caddy
ready_seconds="$(elapsed "$t" "$(now)")"
compose up -d --force-recreate realm-apply
realm_apply_code="$(docker wait "$(compose ps -aq realm-apply)")"
compose logs --no-color realm-apply > "$out/realm-apply-after.txt"
realm_in_sync=false
[ "$realm_apply_code" = 0 ] && grep -qF "signs with the keystore's key" "$out/realm-apply-after.txt" && realm_in_sync=true
read_ok=false
if read_kernel after; then
	read_ok=true
fi
recovery_seconds="$(elapsed "$t0" "$(now)")"

echo "8. compare"
for side in source restored; do
	for part in migration tables sequences roles; do section "$side" "$part"; done
done
schema_equal="$(same schema "$out/schema-source.sql" "$out/schema-restored.sql")"
migration_equal="$(same migration "$out/migration-source.json" "$out/migration-restored.json")"
tables_equal="$(same tables "$out/tables-source.json" "$out/tables-restored.json")"
sequences_equal="$(same sequences "$out/sequences-source.json" "$out/sequences-restored.json")"
roles_equal="$(same roles "$out/roles-source.json" "$out/roles-restored.json")"
read_equal=false
same_kid=false
if [ "$read_ok" = true ]; then
	read_equal="$(same read "$out/read-before.json" "$out/read-after.json")"
	[ -n "$kid" ] && [ "$kid" != null ] && [ "$(jq -r '.active.PS256' "$out/read-after.json")" = "$kid" ] &&
		jq -e --arg k "$kid" '.jwks | index($k)' "$out/read-after.json" > /dev/null && same_kid=true
fi
person_restored=false
jq -e --arg p "$person" '.users | index($p)' "$out/read-after.json" > /dev/null 2>&1 && person_restored=true
volume_new=false
[ "$volume_before" != "$volume_after" ] && volume_new=true

required_json="$(printf '%s\n' "${required[@]}" | jq -R . | jq -s .)"
critical="$(jq --argjson names "$required_json" \
	'[.tables[] | select(.table as $t | $names | index($t)) | {table, rows}]' "$out/fingerprint-source.json")"
critical_filled="$(jq --argjson names "$required_json" \
	'($names | length) == ([.[] | select(.rows > 0)] | length)' <<< "$critical")"
within_rto="$(awk -v s="$recovery_seconds" -v b="$rto_seconds" 'BEGIN { print (s <= b) ? "true" : "false" }')"

jq -n \
	--arg service identity-kernel --arg database "$database" --arg started_at "$started_at" \
	--arg commit "${GITHUB_SHA:-}" \
	--arg run "${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}" \
	--arg postgres "$(compose exec -T postgres postgres --version)" --arg kid "$kid" \
	--argjson backup_seconds "$backup_seconds" --argjson dump_bytes "$dump_bytes" \
	--argjson restore_seconds "$restore_seconds" --argjson ready_seconds "$ready_seconds" \
	--argjson recovery_seconds "$recovery_seconds" --argjson rto_seconds "$rto_seconds" \
	--argjson within_rto "$within_rto" --argjson volume_new "$volume_new" \
	--argjson schema_equal "$schema_equal" --argjson migration_equal "$migration_equal" \
	--argjson tables_equal "$tables_equal" --argjson sequences_equal "$sequences_equal" \
	--argjson roles_equal "$roles_equal" --argjson realm_in_sync "$realm_in_sync" \
	--argjson read_equal "$read_equal" --argjson same_kid "$same_kid" --argjson person_restored "$person_restored" \
	--argjson critical "$critical" --argjson critical_filled "$critical_filled" \
	--argjson refuses_occupied "$refuses_occupied" --argjson one_row_detected "$one_row_detected" \
	--argjson without_roles_refused "$without_roles_refused" --arg probe_table "$probe_table" \
	--argjson failed_backup_kept_all "$failed_backup_kept_all" --argjson kept_newest_14 "$kept_newest_14" \
	--argjson no_keystore_file "$no_keystore_file" --argjson no_keystore_password "$no_keystore_password" \
	--argjson no_private_key "$no_private_key" \
	--slurpfile source "$out/fingerprint-source.json" \
	'{
	  standard: "STD-GLB-002 §Restore Evidence",
	  service: $service, database: $database, started_at: $started_at, commit: $commit, run: $run,
	  postgres: $postgres,
	  backup: {procedure: "deploy/dev/backup.sh", roles: "pg_dumpall --globals-only",
	           database: "pg_dump --format=custom, verified with pg_restore --list",
	           seconds: $backup_seconds, dump_bytes: $dump_bytes},
	  retention: {rule: "the newest 14 complete sets, pruned only after a successful backup (STD-GLB-009 rule 9)",
	              failed_backup_deleted_nothing: $failed_backup_kept_all, newest_14_kept: $kept_newest_14},
	  signing_material: {rule: "the keystore and its password are never copied (STD-GLB-009 rule 9, ADR-IAM-002 §5.3)",
	                     no_keystore_file: $no_keystore_file, no_keystore_password: $no_keystore_password,
	                     no_private_key_in_provider_config: $no_private_key},
	  loss: {procedure: "docker compose down --volumes", new_volume: $volume_new},
	  restore: {procedure: "deploy/dev/restore.sh", seconds: $restore_seconds,
	            refuses_a_cluster_holding_the_database: $refuses_occupied},
	  integrity: {
	    migration: $source[0].migration,
	    tables: ($source[0].tables | length),
	    rows: ([$source[0].tables[].rows] | add),
	    schema_equal: $schema_equal, migration_equal: $migration_equal, tables_equal: $tables_equal,
	    sequences_equal: $sequences_equal, roles_equal: $roles_equal,
	    critical_tables: $critical, critical_tables_filled: $critical_filled
	  },
	  load_bearing: {one_row_removed_from: $probe_table, detected: $one_row_detected,
	                 restore_without_roles_refused: $without_roles_refused},
	  service_check: {ready_seconds: $ready_seconds, realm_apply_in_sync_and_signing_with_the_keystore: $realm_in_sync,
	                  read: "users, the realm revision, the active keys and the published key set",
	                  read_equal: $read_equal, person_restored: $person_restored},
	  key_continuity: {kid: $kid, same_kid_after_restore: $same_kid,
	                   why: "The keystore is outside the database and is not restored: the restored realm loads the same file, so the key set is the one published before (TDD-identity-kernel-002 §Compromise and Recovery)."},
	  rto: {target_seconds: $rto_seconds, recovery_seconds: $recovery_seconds, within: $within_rto,
	        measured: "from restore.sh on an empty volume to the verified read"},
	  rpo: {target_seconds: 60, backup_interval_seconds: 86400, met: false,
	        why: "A daily pg_dump loses up to 24 hours. A 1-minute RPO needs continuous WAL archiving with point-in-time recovery on the production platform; a drill of a logical dump never proves it."},
	  older_point: {drilled: false,
	                why: "The drill restores to the instant of its own backup. A restore to an older point gives back users and clients identity-control has changed since; identity-control reconciles them (its restore runbook)."}
	}' > "$out/restore-evidence.json"

cat "$out/restore-evidence.json"

checks=(schema_equal migration_equal tables_equal sequences_equal roles_equal critical_filled volume_new
	refuses_occupied one_row_detected without_roles_refused failed_backup_kept_all kept_newest_14
	no_keystore_file no_keystore_password no_private_key realm_in_sync read_equal same_kid person_restored within_rto)
failures=0
for check in "${checks[@]}"; do
	if [ "${!check}" = true ]; then
		echo "  ok    $check"
	else
		echo "  FAIL  $check"
		failures=$((failures + 1))
	fi
done
for diff in "$out"/diff-*.txt; do
	[ -e "$diff" ] || continue
	echo "--- $(basename "$diff")"
	head -n 60 "$diff"
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "### Kernel database restore drill"
		echo ""
		echo "| Measure | Value |"
		echo "| :-- | :-- |"
		echo "| Tables, rows | $(jq '.integrity.tables' "$out/restore-evidence.json"), $(jq '.integrity.rows' "$out/restore-evidence.json") |"
		echo "| Backup | ${backup_seconds} s, ${dump_bytes} bytes; retention: failed backup deleted nothing $failed_backup_kept_all, newest 14 kept $kept_newest_14 |"
		echo "| No signing material in the backup | file $no_keystore_file, password $no_keystore_password, private key $no_private_key |"
		echo "| Restore into an empty volume | ${restore_seconds} s |"
		echo "| Recovery, to the verified read | ${recovery_seconds} s, against an RTO of ${rto_seconds} s |"
		echo "| Schema, migration, tables, sequences, roles equal | $schema_equal, $migration_equal, $tables_equal, $sequences_equal, $roles_equal |"
		echo "| Read equal; same kid \`$kid\` | $read_equal; $same_kid |"
		echo "| RPO | not met: a daily dump loses up to 24 h, against 1 min (STD-GLB-002 §Restore Evidence) |"
	} >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$failures" -gt 0 ]; then
	echo "::error::the restore drill failed $failures check(s); see restore-evidence.json"
	exit 1
fi
echo "the kernel database restores, and the realm signs with the same key"
