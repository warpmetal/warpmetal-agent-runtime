#!/bin/sh
# shellcheck disable=SC2034

# Sourced by the signed Runtime installer. Callers keep these values global so
# the installer's EXIT trap can restore the exact prior disk and kernel state.
warpmetal_apparmor_policy_changed=0
warpmetal_apparmor_policy_committed=0
warpmetal_apparmor_policy_had_previous=0
warpmetal_apparmor_policy_prior_setup_loaded=0
warpmetal_apparmor_policy_prior_child_loaded=0
warpmetal_apparmor_policy_error=
warpmetal_apparmor_policy_destination=
warpmetal_apparmor_policy_backup=
warpmetal_apparmor_policy_parser=
warpmetal_apparmor_policy_source=
warpmetal_apparmor_policy_state=
warpmetal_apparmor_policy_metadata_helper=
warpmetal_apparmor_policy_recovery_required=0

# Return 0 when the Runtime policy is required, 1 when AppArmor or the Ubuntu
# restricted-userns control is definitively disabled/absent, and 2 when an
# existing control cannot be read or contains an unexpected value.
warpmetal_detect_apparmor_policy_requirement() {
  enabled_file=$1
  restriction_file=$2
  warpmetal_apparmor_policy_error=

  if [ ! -e "$enabled_file" ] && [ ! -L "$enabled_file" ]; then
    return 1
  fi
  if [ ! -r "$enabled_file" ]; then
    warpmetal_apparmor_policy_error=runtime_apparmor_state_unverifiable
    return 2
  fi
  if ! IFS= read -r apparmor_enabled < "$enabled_file"; then
    warpmetal_apparmor_policy_error=runtime_apparmor_state_unverifiable
    return 2
  fi
  case "$apparmor_enabled" in
    N) return 1 ;;
    Y) ;;
    *)
      warpmetal_apparmor_policy_error=runtime_apparmor_state_unverifiable
      return 2
      ;;
  esac

  if [ ! -e "$restriction_file" ] && [ ! -L "$restriction_file" ]; then
    return 1
  fi
  if [ ! -r "$restriction_file" ]; then
    warpmetal_apparmor_policy_error=runtime_apparmor_state_unverifiable
    return 2
  fi
  if ! IFS= read -r apparmor_restricted_userns < "$restriction_file"; then
    warpmetal_apparmor_policy_error=runtime_apparmor_state_unverifiable
    return 2
  fi
  case "$apparmor_restricted_userns" in
    0) return 1 ;;
    1) return 0 ;;
    *)
      warpmetal_apparmor_policy_error=runtime_apparmor_state_unverifiable
      return 2
      ;;
  esac
}

warpmetal_read_apparmor_loaded_state() {
  policy_state=$1
  if [ ! -r "$policy_state" ]; then
    return 1
  fi
  policy_setup_state=$(awk '$1 == "warpmetal-agent-runtime-bwrap" { count++; if ($2 == "(enforce)") enforce++ } END { print count + 0 ":" enforce + 0 }' "$policy_state") || return 1
  policy_child_state=$(awk '$1 == "warpmetal-agent-runtime-unpriv-bwrap" { count++; if ($2 == "(enforce)") enforce++ } END { print count + 0 ":" enforce + 0 }' "$policy_state") || return 1
  case "$policy_setup_state:$policy_child_state" in
    0:0:0:0|1:1:1:1)
      policy_setup_count=${policy_setup_state%%:*}
      policy_child_count=${policy_child_state%%:*}
      warpmetal_apparmor_setup_loaded=$policy_setup_count
      warpmetal_apparmor_child_loaded=$policy_child_count
      return 0
      ;;
    *) return 2 ;;
  esac
}

warpmetal_install_apparmor_policy() {
  policy_source=$1
  policy_destination=$2
  policy_backup=$3
  policy_parser=$4
  policy_state=$5
  policy_metadata_helper=${6:-$warpmetal_apparmor_policy_metadata_helper}

  warpmetal_apparmor_policy_error=
  warpmetal_apparmor_policy_changed=0
  warpmetal_apparmor_policy_committed=0
  warpmetal_apparmor_policy_had_previous=0
  warpmetal_apparmor_policy_prior_setup_loaded=0
  warpmetal_apparmor_policy_prior_child_loaded=0
  warpmetal_apparmor_policy_destination=$policy_destination
  warpmetal_apparmor_policy_backup=$policy_backup
  warpmetal_apparmor_policy_parser=$policy_parser
  warpmetal_apparmor_policy_source=$policy_source
  warpmetal_apparmor_policy_state=$policy_state
  warpmetal_apparmor_policy_metadata_helper=$policy_metadata_helper
  warpmetal_apparmor_policy_recovery_required=0

  if [ ! -f "$policy_source" ] || [ -L "$policy_source" ]; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_bundle_invalid
    return 1
  fi
  if [ ! -d "${policy_destination%/*}" ]; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_unsupported
    return 1
  fi
  if [ ! -f "$policy_metadata_helper" ] || [ -L "$policy_metadata_helper" ] || \
     [ ! -x "$policy_metadata_helper" ]; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_bundle_invalid
    return 1
  fi

  loaded_state_status=0
  warpmetal_read_apparmor_loaded_state "$policy_state" || loaded_state_status=$?
  case "$loaded_state_status" in
    0) ;;
    1)
      warpmetal_apparmor_policy_error=runtime_apparmor_state_unverifiable
      return 1
      ;;
    *)
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_conflict
      return 1
      ;;
  esac
  warpmetal_apparmor_policy_prior_setup_loaded=$warpmetal_apparmor_setup_loaded
  warpmetal_apparmor_policy_prior_child_loaded=$warpmetal_apparmor_child_loaded

  if [ -e "$policy_destination" ] || [ -L "$policy_destination" ]; then
    if [ ! -f "$policy_destination" ] || [ -L "$policy_destination" ]; then
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_conflict
      return 1
    fi
    if ! "$policy_parser" -Q -K "$policy_destination" >/dev/null 2>&1; then
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_conflict
      return 1
    fi
    if ! cp --preserve=all -- "$policy_destination" "$policy_backup"; then
      warpmetal_apparmor_policy_recovery_required=1
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_backup_failed
      return 1
    fi
    if ! "$policy_metadata_helper" compare "$policy_destination" "$policy_backup" >/dev/null 2>&1; then
      warpmetal_apparmor_policy_recovery_required=1
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_backup_failed
      return 1
    fi
    warpmetal_apparmor_policy_had_previous=1
  elif [ "$warpmetal_apparmor_policy_prior_setup_loaded" -ne 0 ] || \
       [ "$warpmetal_apparmor_policy_prior_child_loaded" -ne 0 ]; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_conflict
    return 1
  fi

  if ! "$policy_parser" -Q -K "$policy_source" >/dev/null 2>&1; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_parse_failed
    return 1
  fi

  policy_staged=$(mktemp "${policy_destination%/*}/.warpmetal-agent-runtime-bwrap.XXXXXX") || {
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_install_failed
    return 1
  }
  # The signed installer requires UID 0 before this helper is sourced, so a
  # newly created file is root-owned without accepting an owner from input.
  if ! install -m 0644 "$policy_source" "$policy_staged"; then
    rm -f -- "$policy_staged" >/dev/null 2>&1 || true
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_install_failed
    return 1
  fi
  if ! mv -f -- "$policy_staged" "$policy_destination"; then
    rm -f -- "$policy_staged" >/dev/null 2>&1 || true
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_install_failed
    return 1
  fi
  warpmetal_apparmor_policy_changed=1

  if ! "$policy_parser" -r -K "$policy_destination" >/dev/null 2>&1; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_load_failed
    return 1
  fi
  loaded_state_status=0
  warpmetal_read_apparmor_loaded_state "$policy_state" || loaded_state_status=$?
  if [ "$loaded_state_status" -ne 0 ] || \
     [ "$warpmetal_apparmor_setup_loaded" -ne 1 ] || \
     [ "$warpmetal_apparmor_child_loaded" -ne 1 ]; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_load_failed
    return 1
  fi
}

warpmetal_rollback_apparmor_policy() {
  if [ "$warpmetal_apparmor_policy_changed" -ne 1 ]; then
    return 0
  fi
  if [ "$warpmetal_apparmor_policy_committed" -eq 1 ]; then
    return 0
  fi

  rollback_status=0
  restore_file_ready=1

  # Remove both candidate definitions before restoring a previous policy. The
  # source is retained in the signed bundle even if the destination was altered.
  if ! "$warpmetal_apparmor_policy_parser" -R -K "$warpmetal_apparmor_policy_source" >/dev/null 2>&1; then
    rollback_status=1
  fi

  if [ "$warpmetal_apparmor_policy_had_previous" -eq 1 ]; then
    rollback_staged=$(mktemp "${warpmetal_apparmor_policy_destination%/*}/.warpmetal-agent-runtime-bwrap.rollback.XXXXXX") || {
      rollback_status=1
      restore_file_ready=0
      rollback_staged=
    }
    if [ "$restore_file_ready" -eq 1 ]; then
      if ! cp --preserve=all -- "$warpmetal_apparmor_policy_backup" "$rollback_staged"; then
        rollback_status=1
        restore_file_ready=0
      fi
    fi
    if [ "$restore_file_ready" -eq 1 ]; then
      if ! "$warpmetal_apparmor_policy_metadata_helper" compare \
        "$warpmetal_apparmor_policy_backup" "$rollback_staged" >/dev/null 2>&1; then
        rollback_status=1
        restore_file_ready=0
      fi
    fi
    if [ "$restore_file_ready" -eq 1 ]; then
      if ! mv -f -- "$rollback_staged" "$warpmetal_apparmor_policy_destination"; then
        rollback_status=1
        restore_file_ready=0
      fi
    fi
    if [ -n "$rollback_staged" ] && [ -e "$rollback_staged" ]; then
      if ! rm -f -- "$rollback_staged"; then
        rollback_status=1
      fi
    fi
    if [ "$restore_file_ready" -eq 1 ] && \
       [ "$warpmetal_apparmor_policy_prior_setup_loaded" -eq 1 ] && \
       [ "$warpmetal_apparmor_policy_prior_child_loaded" -eq 1 ]; then
      if ! "$warpmetal_apparmor_policy_parser" -r -K "$warpmetal_apparmor_policy_destination" >/dev/null 2>&1; then
        rollback_status=1
      fi
      # apparmor_parser reads the restored file. On strict-atime mounts, and on
      # relatime mounts when the preserved atime is old, that read advances
      # atime even though the policy itself was restored exactly. Restore both
      # nanosecond timestamps from the preserved backup before the final,
      # O_NOATIME metadata comparison. Any failure remains a failed rollback.
      if ! touch --no-dereference --reference="$warpmetal_apparmor_policy_backup" \
        "$warpmetal_apparmor_policy_destination"; then
        rollback_status=1
      fi
    fi
  else
    if ! rm -f -- "$warpmetal_apparmor_policy_destination"; then
      rollback_status=1
    fi
  fi

  if [ "$warpmetal_apparmor_policy_had_previous" -eq 1 ]; then
    if [ ! -f "$warpmetal_apparmor_policy_destination" ] || \
       ! "$warpmetal_apparmor_policy_metadata_helper" compare \
         "$warpmetal_apparmor_policy_backup" "$warpmetal_apparmor_policy_destination" >/dev/null 2>&1; then
      rollback_status=1
    fi
  elif [ -e "$warpmetal_apparmor_policy_destination" ] || \
       [ -L "$warpmetal_apparmor_policy_destination" ]; then
    rollback_status=1
  fi

  loaded_state_status=0
  warpmetal_read_apparmor_loaded_state "$warpmetal_apparmor_policy_state" || loaded_state_status=$?
  if [ "$loaded_state_status" -ne 0 ] || \
     [ "$warpmetal_apparmor_setup_loaded" -ne "$warpmetal_apparmor_policy_prior_setup_loaded" ] || \
     [ "$warpmetal_apparmor_child_loaded" -ne "$warpmetal_apparmor_policy_prior_child_loaded" ]; then
    rollback_status=1
  fi

  if [ "$rollback_status" -eq 0 ]; then
    return 0
  fi
  warpmetal_apparmor_policy_recovery_required=1
  return 1
}
