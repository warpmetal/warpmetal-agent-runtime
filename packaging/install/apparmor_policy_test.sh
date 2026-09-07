#!/bin/sh
# shellcheck disable=SC2034,SC2154
set -eu

# shellcheck source=/dev/null
. packaging/install/warpmetal-apparmor-policy.sh

command -v python3 >/dev/null 2>&1 || {
  echo apparmor_policy_test_requires_python3 >&2
  exit 1
}
command -v go >/dev/null 2>&1 || {
  echo apparmor_policy_test_requires_go >&2
  exit 1
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/warpmetal-apparmor-test.XXXXXX")
cleanup() {
  chmod 0700 "$test_root" "$test_root/etc/apparmor.d" 2>/dev/null || true
  rm -rf -- "$test_root"
}
trap cleanup 0 1 2 15

fail_test() {
  echo "$1" >&2
  exit 1
}

expect_status() {
  expected_status=$1
  shift
  actual_status=0
  "$@" || actual_status=$?
  [ "$actual_status" -eq "$expected_status" ] || \
    fail_test "unexpected_status expected=$expected_status actual=$actual_status"
}

mkdir -p "$test_root/etc/apparmor.d" "$test_root/state" "$test_root/bin"
parser=$test_root/apparmor_parser
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'printf "PARSER %s %s %s\\n" "$1" "$2" "$3" >> "$APPARMOR_TEST_LOG"' \
  'remove_profiles() {' \
  '  awk '\''$1 != "warpmetal-agent-runtime-bwrap" && $1 != "warpmetal-agent-runtime-unpriv-bwrap"'\'' "$APPARMOR_TEST_STATE" > "$APPARMOR_TEST_STATE.tmp"' \
  '  mv "$APPARMOR_TEST_STATE.tmp" "$APPARMOR_TEST_STATE"' \
  '}' \
  'case "$1" in' \
  '  -Q)' \
  '    test "$2" = -K' \
  '    if grep -Fq FAIL_PARSE "$3"; then exit 1; fi' \
  '    ;;' \
  '  -r)' \
  '    test "$2" = -K' \
  '    if grep -Fq FAIL_LOAD_PARTIAL "$3"; then' \
  '      remove_profiles' \
  '      printf "warpmetal-agent-runtime-bwrap (enforce)\\n" >> "$APPARMOR_TEST_STATE"' \
  '      exit 1' \
  '    fi' \
  '    if grep -Fq FAIL_LOAD "$3"; then exit 1; fi' \
  '    remove_profiles' \
  '    printf "%s\\n" "warpmetal-agent-runtime-bwrap (enforce)" "warpmetal-agent-runtime-unpriv-bwrap (enforce)" >> "$APPARMOR_TEST_STATE"' \
  '    ;;' \
  '  -R)' \
  '    test "$2" = -K' \
  '    if [ "${APPARMOR_TEST_REMOVE_STATUS:-0}" -ne 0 ]; then exit "$APPARMOR_TEST_REMOVE_STATUS"; fi' \
  '    remove_profiles' \
  '    ;;' \
  '  *) exit 2 ;;' \
  'esac' > "$parser"
chmod 0755 "$parser"

metadata_helper=$test_root/warpmetal-policy-metadata
metadata_binary=$test_root/warpmetal-policy-metadata.real
go build -o "$metadata_binary" ./cmd/warpmetal-policy-metadata
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'printf "METADATA %s %s %s\\n" "$1" "$2" "$3" >> "$APPARMOR_TEST_LOG"' \
  'if [ "${APPARMOR_TEST_METADATA_FAIL_TARGET:-}" = "$3" ]; then "$APPARMOR_TEST_METADATA_BINARY" "$@"; exit 9; fi' \
  'case "${APPARMOR_TEST_METADATA_FAIL_KIND:-}" in restore) case "$3" in */.warpmetal-agent-runtime-bwrap.rollback.*/*) "$APPARMOR_TEST_METADATA_BINARY" "$@"; exit 9 ;; esac ;; esac' \
  'exec "$APPARMOR_TEST_METADATA_BINARY" "$@"' > "$metadata_helper"
chmod 0755 "$metadata_helper"
export APPARMOR_TEST_METADATA_BINARY="$metadata_binary"
warpmetal_apparmor_policy_metadata_helper=$metadata_helper

export APPARMOR_TEST_LOG="$test_root/operations.log"
export APPARMOR_TEST_STATE="$test_root/apparmor-profiles"
policy_state=$APPARMOR_TEST_STATE
: > "$policy_state"

enabled=$test_root/apparmor-enabled
restricted=$test_root/restricted-userns
printf 'Y\n' > "$enabled"
printf '1\n' > "$restricted"
expect_status 0 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
printf 'N\n' > "$enabled"
expect_status 1 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
printf 'unexpected\n' > "$enabled"
expect_status 2 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_state_unverifiable
rm -f -- "$enabled"
expect_status 1 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
ln -s "$test_root/missing-enabled" "$enabled"
expect_status 2 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
rm -f -- "$enabled"
printf 'Y\n' > "$enabled"
rm -f -- "$restricted"
expect_status 1 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
ln -s "$test_root/missing-restriction" "$restricted"
expect_status 2 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
rm -f -- "$restricted"
printf '2\n' > "$restricted"
expect_status 2 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
printf '0\n' > "$restricted"
expect_status 1 warpmetal_detect_apparmor_policy_requirement "$enabled" "$restricted"
printf '1\n' > "$restricted"

candidate=$test_root/candidate
destination=$test_root/etc/apparmor.d/warpmetal-agent-runtime-bwrap
backup=$test_root/state/previous
printf 'candidate profile\n' > "$candidate"

# A metadata mismatch in the backup fails before policy mutation and requests
# preservation of the recovery directory.
printf 'previous profile\n' > "$destination"
: > "$policy_state"
export APPARMOR_TEST_METADATA_FAIL_TARGET="$backup"
expect_status 1 warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
unset APPARMOR_TEST_METADATA_FAIL_TARGET
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_policy_backup_failed
test "$warpmetal_apparmor_policy_recovery_required" -eq 1
cmp -s "$destination" "$backup"
rm -f -- "$destination" "$backup"

# Clean first install loads both profiles and rollback returns to no file and no
# loaded definitions.
: > "$APPARMOR_TEST_LOG"
: > "$policy_state"
warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
cmp -s "$candidate" "$destination"
grep -Fqx -- "PARSER -Q -K $candidate" "$APPARMOR_TEST_LOG"
grep -Fqx -- "PARSER -r -K $destination" "$APPARMOR_TEST_LOG"
grep -Fqx 'warpmetal-agent-runtime-bwrap (enforce)' "$policy_state"
grep -Fqx 'warpmetal-agent-runtime-unpriv-bwrap (enforce)' "$policy_state"
warpmetal_rollback_apparmor_policy
[ ! -e "$destination" ] || fail_test first_install_file_not_removed
test ! -s "$policy_state"

# A disk policy that was loaded is restored as loaded after candidate removal.
printf 'previous profile\n' > "$destination"
python3 -c 'import os,struct,sys; p=sys.argv[1]; os.chmod(p,0o640); os.setxattr(p,"user.warpmetal_test",b"preserve-me"); acl=struct.pack("<I",2)+b"".join(struct.pack("<HHI",tag,perm,ident) for tag,perm,ident in [(1,7,0xffffffff),(2,4,os.getuid()+1),(4,4,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)]); os.setxattr(p,"system.posix_acl_access",acl); default=struct.pack("<I",2)+b"".join(struct.pack("<HHI",tag,perm,ident) for tag,perm,ident in [(1,7,0xffffffff),(4,4,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)]); [os.setxattr(d,"system.posix_acl_default",default) for d in sys.argv[2:]]; os.utime(p,ns=(1700000000000000000,1700000000000000000)); os.chown(p,123,456) if os.geteuid()==0 else None' "$destination" "$test_root/state" "$test_root/etc/apparmor.d"
metadata_command='import json,os,stat,sys; p=sys.argv[1]; s=os.stat(p,follow_symlinks=False); x={n:os.getxattr(p,n,follow_symlinks=False).hex() for n in sorted(os.listxattr(p,follow_symlinks=False))}; print(json.dumps([s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_atime_ns,s.st_mtime_ns,x],sort_keys=True))'
previous_metadata=$(python3 -c "$metadata_command" "$destination")
source_atime_before=$(python3 -c 'import os,sys; print(os.stat(sys.argv[1],follow_symlinks=False).st_atime_ns)' "$destination")
"$metadata_binary" copy "$destination" "$test_root/expected-previous"
source_atime_after=$(python3 -c 'import os,sys; print(os.stat(sys.argv[1],follow_symlinks=False).st_atime_ns)' "$destination")
test "$source_atime_after" = "$source_atime_before"
printf '%s\n' 'warpmetal-agent-runtime-bwrap (enforce)' 'warpmetal-agent-runtime-unpriv-bwrap (enforce)' > "$policy_state"
: > "$APPARMOR_TEST_LOG"
warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
test "$(python3 -c "$metadata_command" "$backup")" = "$previous_metadata"
warpmetal_rollback_apparmor_policy
"$metadata_binary" compare "$test_root/expected-previous" "$destination"
test "$(python3 -c "$metadata_command" "$destination")" = "$previous_metadata"
test "$(grep -Fxc -- "PARSER -r -K $destination" "$APPARMOR_TEST_LOG")" -eq 2
grep -Fqx 'warpmetal-agent-runtime-bwrap (enforce)' "$policy_state"
grep -Fqx 'warpmetal-agent-runtime-unpriv-bwrap (enforce)' "$policy_state"

# Timestamp restoration is fail-closed after the parser reads an old-atime
# restored policy. The backup is retained as recovery evidence.
rm -f -- "$backup"
warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
original_path=$PATH
printf '%s\n' \
  '#!/bin/sh' \
  'if [ "${APPARMOR_TEST_TOUCH_FAIL:-0}" -eq 1 ]; then exit 9; fi' \
  'exec /usr/bin/touch "$@"' > "$test_root/bin/touch"
chmod 0755 "$test_root/bin/touch"
export APPARMOR_TEST_TOUCH_FAIL=1
PATH=$test_root/bin:$PATH
export PATH
expect_status 1 warpmetal_rollback_apparmor_policy
PATH=$original_path
export PATH
unset APPARMOR_TEST_TOUCH_FAIL
test "$warpmetal_apparmor_policy_recovery_required" -eq 1
test -f "$backup"
# Reset this deliberately failed fixture from its retained backup.
rm -f -- "$destination"
"$metadata_binary" copy "$backup" "$destination"
printf '%s\n' 'warpmetal-agent-runtime-bwrap (enforce)' 'warpmetal-agent-runtime-unpriv-bwrap (enforce)' > "$policy_state"
rm -f -- "$backup"

# A restore metadata mismatch blocks replacement, retains the backup, and marks
# recovery evidence for preservation.
printf 'candidate profile\n' > "$candidate"
warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
export APPARMOR_TEST_METADATA_FAIL_KIND=restore
expect_status 1 warpmetal_rollback_apparmor_policy
unset APPARMOR_TEST_METADATA_FAIL_KIND
test "$warpmetal_apparmor_policy_recovery_required" -eq 1
test -f "$backup"
# Complete this fixture's cleanup before the remaining independent cases.
rm -f -- "$destination"
"$metadata_binary" copy "$backup" "$destination"
: > "$policy_state"
rm -f -- "$backup"

# A disk policy that was not loaded remains unloaded after rollback.
: > "$policy_state"
: > "$APPARMOR_TEST_LOG"
warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
warpmetal_rollback_apparmor_policy
"$metadata_binary" compare "$test_root/expected-previous" "$destination"
test "$(grep -Fxc -- "PARSER -r -K $destination" "$APPARMOR_TEST_LOG")" -eq 1
test ! -s "$policy_state"

# Every partial or mismatched kernel/disk combination fails before mutation.
rm -f -- "$destination"
printf 'warpmetal-agent-runtime-bwrap (enforce)\n' > "$policy_state"
expect_status 1 warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_policy_conflict
[ ! -e "$destination" ] || fail_test conflict_created_destination
printf '%s\n' 'warpmetal-agent-runtime-bwrap (enforce)' 'warpmetal-agent-runtime-unpriv-bwrap (enforce)' > "$policy_state"
expect_status 1 warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_policy_conflict
printf 'previous profile\n' > "$destination"
printf 'warpmetal-agent-runtime-unpriv-bwrap (enforce)\n' > "$policy_state"
expect_status 1 warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_policy_conflict
printf '%s\n' 'warpmetal-agent-runtime-bwrap (complain)' 'warpmetal-agent-runtime-unpriv-bwrap (complain)' > "$policy_state"
expect_status 1 warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_policy_conflict
printf '%s\n' 'warpmetal-agent-runtime-bwrap (enforce)' 'warpmetal-agent-runtime-unpriv-bwrap (kill)' > "$policy_state"
expect_status 1 warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_policy_conflict

# Parse failure leaves both states untouched.
# Each real installer invocation has a fresh root-only state directory; remove
# the preceding fixture's backup so this invocation exercises that contract.
rm -f -- "$backup"
: > "$policy_state"
printf 'FAIL_PARSE\n' > "$candidate"
expect_status 1 warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_policy_parse_failed
cmp -s "$test_root/expected-previous" "$destination"
test ! -s "$policy_state"

# A partial first load is removed completely during rollback.
rm -f -- "$destination"
printf 'FAIL_LOAD_PARTIAL\n' > "$candidate"
: > "$policy_state"
expect_status 1 warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
test "$warpmetal_apparmor_policy_error" = runtime_apparmor_policy_load_failed
grep -Fqx 'warpmetal-agent-runtime-bwrap (enforce)' "$policy_state"
warpmetal_rollback_apparmor_policy
test ! -s "$policy_state"
[ ! -e "$destination" ] || fail_test partial_load_file_not_removed

# Aggregate unload and destination-removal failures; both operations are
# attempted and rollback reports failure with the recovery file retained.
printf 'candidate profile\n' > "$candidate"
: > "$policy_state"
warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
original_path=$PATH
printf '%s\n' \
  '#!/bin/sh' \
  'printf "RM %s\\n" "$*" >> "$APPARMOR_TEST_LOG"' \
  'for argument in "$@"; do' \
  '  if [ "$argument" = "$APPARMOR_TEST_RM_FAIL" ]; then exit 9; fi' \
  'done' \
  'exec /bin/rm "$@"' > "$test_root/bin/rm"
chmod 0755 "$test_root/bin/rm"
export APPARMOR_TEST_REMOVE_STATUS=8
export APPARMOR_TEST_RM_FAIL="$destination"
PATH=$test_root/bin:$PATH
export PATH
expect_status 1 warpmetal_rollback_apparmor_policy
PATH=$original_path
export PATH
unset APPARMOR_TEST_REMOVE_STATUS APPARMOR_TEST_RM_FAIL
grep -Fqx -- "PARSER -R -K $candidate" "$APPARMOR_TEST_LOG"
grep -Fqx -- "RM -f -- $destination" "$APPARMOR_TEST_LOG"
test -e "$destination"
/bin/rm -f -- "$destination"
: > "$policy_state"

# A committed candidate is retained by the installer EXIT path.
warpmetal_install_apparmor_policy "$candidate" "$destination" "$backup" "$parser" "$policy_state"
warpmetal_apparmor_policy_committed=1
warpmetal_rollback_apparmor_policy
cmp -s "$candidate" "$destination"
grep -Fqx 'warpmetal-agent-runtime-bwrap (enforce)' "$policy_state"
grep -Fqx 'warpmetal-agent-runtime-unpriv-bwrap (enforce)' "$policy_state"
