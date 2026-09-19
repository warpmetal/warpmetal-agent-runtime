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
warpmetal_apparmor_policy_durable_state=
warpmetal_apparmor_policy_operation=

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
    if ! "$policy_metadata_helper" copy "$policy_destination" "$policy_backup" >/dev/null 2>&1; then
      warpmetal_apparmor_policy_recovery_required=1
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_backup_failed
      return 1
    fi
    if ! "$policy_metadata_helper" compare "$policy_destination" "$policy_backup" >/dev/null 2>&1; then
      warpmetal_apparmor_policy_recovery_required=1
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_backup_failed
      return 1
    fi
    existing_parse_status=0
    "$policy_parser" -Q -K "$policy_destination" >/dev/null 2>&1 || existing_parse_status=$?
    # Syntax inspection reads the existing policy. Restore its exact reference
    # timestamps from the no-atime backup before accepting either result.
    if ! touch --no-dereference --reference="$policy_backup" "$policy_destination" || \
       ! "$policy_metadata_helper" compare "$policy_backup" "$policy_destination" >/dev/null 2>&1; then
      warpmetal_apparmor_policy_recovery_required=1
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_backup_failed
      return 1
    fi
    if [ "$existing_parse_status" -ne 0 ]; then
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_conflict
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
  if ! warpmetal_sync_apparmor_path "${policy_destination%/*}"; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_install_failed
    return 1
  fi

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

warpmetal_rollback_apparmor_policy_legacy() {
  if [ "$warpmetal_apparmor_policy_changed" -ne 1 ]; then
    return 0
  fi
  if [ "$warpmetal_apparmor_policy_committed" -eq 1 ]; then
    return 0
  fi

  rollback_status=0
  restore_file_ready=1
  rollback_directory=

  # Remove both candidate definitions before restoring a previous policy. The
  # source is retained in the signed bundle even if the destination was altered.
  if ! "$warpmetal_apparmor_policy_parser" -R -K "$warpmetal_apparmor_policy_source" >/dev/null 2>&1; then
    rollback_status=1
  fi

  if [ "$warpmetal_apparmor_policy_had_previous" -eq 1 ]; then
    rollback_directory=$(mktemp -d "${warpmetal_apparmor_policy_destination%/*}/.warpmetal-agent-runtime-bwrap.rollback.XXXXXX") || {
      rollback_status=1
      restore_file_ready=0
      rollback_staged=
    }
    if [ "$restore_file_ready" -eq 1 ]; then
      rollback_staged=$rollback_directory/policy
      if ! "$warpmetal_apparmor_policy_metadata_helper" copy \
        "$warpmetal_apparmor_policy_backup" "$rollback_staged" >/dev/null 2>&1; then
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
    if [ -n "$rollback_directory" ] && [ -d "$rollback_directory" ]; then
      if ! rmdir -- "$rollback_directory"; then
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

warpmetal_sync_apparmor_path() {
  sync -f "$1" >/dev/null 2>&1
}

warpmetal_write_apparmor_state_value() {
  state_value_path=$1
  state_value=$2
  printf '%s\n' "$state_value" > "$state_value_path" || return 1
  chmod 0600 "$state_value_path" || return 1
  warpmetal_sync_apparmor_path "$state_value_path"
}

warpmetal_read_apparmor_snapshot() {
  snapshot_directory=$1
  if [ ! -d "$snapshot_directory" ] || [ -L "$snapshot_directory" ]; then
    return 1
  fi
  snapshot_identity=$(stat -c '%u:%g:%a' "$snapshot_directory" 2>/dev/null) || return 1
  [ "$snapshot_identity" = 0:0:700 ] || return 1
  for snapshot_field in had-policy setup-loaded child-loaded; do
    snapshot_field_path=$snapshot_directory/$snapshot_field
    if [ ! -f "$snapshot_field_path" ] || [ -L "$snapshot_field_path" ]; then
      return 1
    fi
    IFS= read -r snapshot_field_value < "$snapshot_field_path" || return 1
    case "$snapshot_field_value" in 0|1) ;; *) return 1 ;; esac
    case "$snapshot_field" in
      had-policy) warpmetal_snapshot_had_policy=$snapshot_field_value ;;
      setup-loaded) warpmetal_snapshot_setup_loaded=$snapshot_field_value ;;
      child-loaded) warpmetal_snapshot_child_loaded=$snapshot_field_value ;;
    esac
  done
  if [ "$warpmetal_snapshot_setup_loaded" -ne "$warpmetal_snapshot_child_loaded" ]; then
    return 1
  fi
  snapshot_policy=$snapshot_directory/policy
  if [ "$warpmetal_snapshot_had_policy" -eq 1 ]; then
    [ -f "$snapshot_policy" ] && [ ! -L "$snapshot_policy" ] || return 1
  elif [ -e "$snapshot_policy" ] || [ -L "$snapshot_policy" ]; then
    return 1
  fi
}

warpmetal_prepare_apparmor_durable_state() {
  durable_state=$1
  durable_parent=${durable_state%/*}
  if [ -e "$durable_parent" ] || [ -L "$durable_parent" ]; then
    [ -d "$durable_parent" ] && [ ! -L "$durable_parent" ] || return 1
  else
    install -d -o root -g root -m 0700 "$durable_parent" || return 1
  fi
  if [ -e "$durable_state" ] || [ -L "$durable_state" ]; then
    [ -d "$durable_state" ] && [ ! -L "$durable_state" ] || return 1
  else
    install -d -o root -g root -m 0700 "$durable_state" || return 1
    warpmetal_sync_apparmor_path "$durable_parent" || return 1
  fi
  durable_identity=$(stat -c '%u:%g:%a' "$durable_state" 2>/dev/null) || return 1
  [ "$durable_identity" = 0:0:700 ] || return 1
}

warpmetal_remove_apparmor_completed_state() {
  completed_state=$1/completed
  if [ -e "$completed_state" ] || [ -L "$completed_state" ]; then
    [ -d "$completed_state" ] && [ ! -L "$completed_state" ] || return 1
    rm -rf -- "$completed_state" || return 1
    warpmetal_sync_apparmor_path "$1" || return 1
  fi
}

warpmetal_snapshot_apparmor_policy() {
  snapshot_root=$1
  snapshot_mode=$2
  snapshot_destination=$3
  snapshot_parser=$4
  snapshot_state=$5
  snapshot_metadata_helper=$6

  snapshot_status=0
  warpmetal_read_apparmor_loaded_state "$snapshot_state" || snapshot_status=$?
  [ "$snapshot_status" -eq 0 ] || return 1

  snapshot_had_policy=0
  if [ -e "$snapshot_destination" ] || [ -L "$snapshot_destination" ]; then
    [ -f "$snapshot_destination" ] && [ ! -L "$snapshot_destination" ] || return 1
    snapshot_had_policy=1
  elif [ "$warpmetal_apparmor_setup_loaded" -ne 0 ] || \
       [ "$warpmetal_apparmor_child_loaded" -ne 0 ]; then
    return 1
  fi

  snapshot_temporary=$(mktemp -d "$snapshot_root/.transaction.XXXXXX") || return 1
  snapshot_ready=0
  if warpmetal_write_apparmor_state_value "$snapshot_temporary/had-policy" "$snapshot_had_policy" && \
     warpmetal_write_apparmor_state_value "$snapshot_temporary/setup-loaded" "$warpmetal_apparmor_setup_loaded" && \
     warpmetal_write_apparmor_state_value "$snapshot_temporary/child-loaded" "$warpmetal_apparmor_child_loaded" && \
     warpmetal_write_apparmor_state_value "$snapshot_temporary/operation" "$snapshot_mode"; then
    snapshot_ready=1
  fi
  if [ "$snapshot_ready" -eq 1 ] && [ "$snapshot_had_policy" -eq 1 ]; then
    if ! "$snapshot_metadata_helper" copy \
      "$snapshot_destination" "$snapshot_temporary/policy" >/dev/null 2>&1 || \
       ! "$snapshot_metadata_helper" compare \
      "$snapshot_destination" "$snapshot_temporary/policy" >/dev/null 2>&1; then
      snapshot_ready=0
    fi
    if [ "$snapshot_ready" -eq 1 ]; then
      snapshot_parse_status=0
      "$snapshot_parser" -Q -K "$snapshot_destination" >/dev/null 2>&1 || snapshot_parse_status=$?
      if ! touch --no-dereference --reference="$snapshot_temporary/policy" \
        "$snapshot_destination" || \
         ! "$snapshot_metadata_helper" compare \
        "$snapshot_temporary/policy" "$snapshot_destination" >/dev/null 2>&1 || \
         [ "$snapshot_parse_status" -ne 0 ]; then
        snapshot_ready=0
      fi
    fi
  fi
  if [ "$snapshot_ready" -eq 1 ]; then
    warpmetal_sync_apparmor_path "$snapshot_temporary" || snapshot_ready=0
  fi
  if [ "$snapshot_ready" -eq 1 ] && \
     mv -- "$snapshot_temporary" "$snapshot_root/transaction" && \
     warpmetal_sync_apparmor_path "$snapshot_root"; then
    return 0
  fi
  rm -rf -- "$snapshot_temporary" >/dev/null 2>&1 || true
  return 1
}

warpmetal_restore_apparmor_snapshot() {
  restore_snapshot=$1
  restore_destination=$2
  restore_source=$3
  restore_parser=$4
  restore_state=$5
  restore_metadata_helper=$6

  warpmetal_read_apparmor_snapshot "$restore_snapshot" || return 1
  restore_had_policy=$warpmetal_snapshot_had_policy
  restore_setup_loaded=$warpmetal_snapshot_setup_loaded
  restore_child_loaded=$warpmetal_snapshot_child_loaded
  restore_status=0

  if grep -Eq '^(warpmetal-agent-runtime-bwrap|warpmetal-agent-runtime-unpriv-bwrap)[[:space:]]' \
    "$restore_state" 2>/dev/null; then
    "$restore_parser" -R -K "$restore_source" >/dev/null 2>&1 || restore_status=1
  fi

  if [ "$restore_had_policy" -eq 1 ]; then
    restore_directory=$(mktemp -d "${restore_destination%/*}/.warpmetal-agent-runtime-bwrap.rollback.XXXXXX") || return 1
    restore_staged=$restore_directory/policy
    if ! "$restore_metadata_helper" copy \
      "$restore_snapshot/policy" "$restore_staged" >/dev/null 2>&1 || \
       ! "$restore_metadata_helper" compare \
      "$restore_snapshot/policy" "$restore_staged" >/dev/null 2>&1 || \
       ! mv -f -- "$restore_staged" "$restore_destination"; then
      restore_status=1
    fi
    if [ -e "$restore_staged" ] && ! rm -f -- "$restore_staged"; then
      restore_status=1
    fi
    if ! rmdir -- "$restore_directory"; then
      restore_status=1
    fi
  elif ! rm -f -- "$restore_destination"; then
    restore_status=1
  fi
  warpmetal_sync_apparmor_path "${restore_destination%/*}" || restore_status=1

  if [ "$restore_had_policy" -eq 1 ] && [ "$restore_setup_loaded" -eq 1 ]; then
    "$restore_parser" -r -K "$restore_destination" >/dev/null 2>&1 || restore_status=1
    if ! touch --no-dereference --reference="$restore_snapshot/policy" \
      "$restore_destination"; then
      restore_status=1
    fi
  fi

  if [ "$restore_had_policy" -eq 1 ]; then
    if [ ! -f "$restore_destination" ] || \
       ! "$restore_metadata_helper" compare \
      "$restore_snapshot/policy" "$restore_destination" >/dev/null 2>&1; then
      restore_status=1
    fi
  elif [ -e "$restore_destination" ] || [ -L "$restore_destination" ]; then
    restore_status=1
  fi

  restore_loaded_status=0
  warpmetal_read_apparmor_loaded_state "$restore_state" || restore_loaded_status=$?
  if [ "$restore_loaded_status" -ne 0 ] || \
     [ "$warpmetal_apparmor_setup_loaded" -ne "$restore_setup_loaded" ] || \
     [ "$warpmetal_apparmor_child_loaded" -ne "$restore_child_loaded" ]; then
    restore_status=1
  fi
  [ "$restore_status" -eq 0 ]
}

warpmetal_recover_apparmor_transaction() {
  recover_root=$1
  recover_destination=$2
  recover_source=$3
  recover_parser=$4
  recover_state=$5
  recover_metadata_helper=$6
  recover_transaction=$recover_root/transaction

  if [ ! -e "$recover_transaction" ] && [ ! -L "$recover_transaction" ]; then
    return 0
  fi
  warpmetal_restore_apparmor_snapshot \
    "$recover_transaction" "$recover_destination" "$recover_source" \
    "$recover_parser" "$recover_state" "$recover_metadata_helper" || return 1
  if [ -d "$recover_transaction/activation-baseline" ] && \
     [ ! -L "$recover_transaction/activation-baseline" ]; then
    if [ -e "$recover_root/baseline" ] || [ -L "$recover_root/baseline" ]; then
      return 1
    fi
    mv -- "$recover_transaction/activation-baseline" "$recover_root/baseline" || return 1
  fi
  rm -rf -- "$recover_transaction" || return 1
  warpmetal_sync_apparmor_path "$recover_root"
}

warpmetal_create_empty_apparmor_baseline() {
  baseline_root=$1
  baseline_temporary=$(mktemp -d "$baseline_root/.baseline.XXXXXX") || return 1
  baseline_ready=0
  if warpmetal_write_apparmor_state_value "$baseline_temporary/had-policy" 0 && \
     warpmetal_write_apparmor_state_value "$baseline_temporary/setup-loaded" 0 && \
     warpmetal_write_apparmor_state_value "$baseline_temporary/child-loaded" 0 && \
     warpmetal_sync_apparmor_path "$baseline_temporary"; then
    baseline_ready=1
  fi
  if [ "$baseline_ready" -eq 1 ] && \
     mv -- "$baseline_temporary" "$baseline_root/baseline" && \
     warpmetal_sync_apparmor_path "$baseline_root"; then
    return 0
  fi
  rm -rf -- "$baseline_temporary" >/dev/null 2>&1 || true
  return 1
}

warpmetal_candidate_apparmor_policy_active() {
  candidate_source=$1
  candidate_destination=$2
  candidate_state=$3
  candidate_metadata_helper=$4
  [ -f "$candidate_destination" ] && [ ! -L "$candidate_destination" ] || return 1
  "$candidate_metadata_helper" content-equal \
    "$candidate_source" "$candidate_destination" >/dev/null 2>&1 || return 1
  candidate_loaded_status=0
  warpmetal_read_apparmor_loaded_state "$candidate_state" || candidate_loaded_status=$?
  [ "$candidate_loaded_status" -eq 0 ] && \
    [ "$warpmetal_apparmor_setup_loaded" -eq 1 ] && \
    [ "$warpmetal_apparmor_child_loaded" -eq 1 ]
}

warpmetal_configure_apparmor_policy() {
  configure_mode=$1
  configure_architecture=$2
  configure_source=$3
  configure_destination=$4
  configure_durable_state=$5
  configure_parser=$6
  configure_state=$7
  configure_metadata_helper=$8

  warpmetal_apparmor_policy_error=
  warpmetal_apparmor_policy_changed=0
  warpmetal_apparmor_policy_committed=0
  warpmetal_apparmor_policy_operation=
  warpmetal_apparmor_policy_durable_state=$configure_durable_state
  warpmetal_apparmor_policy_destination=$configure_destination
  warpmetal_apparmor_policy_source=$configure_source
  warpmetal_apparmor_policy_parser=$configure_parser
  warpmetal_apparmor_policy_state=$configure_state
  warpmetal_apparmor_policy_metadata_helper=$configure_metadata_helper
  warpmetal_apparmor_policy_recovery_required=0

  case "$configure_mode" in
    preserve) return 0 ;;
    enable|disable) ;;
    *)
      warpmetal_apparmor_policy_error=runtime_nested_private_procfs_mode_invalid
      return 1
      ;;
  esac
  if [ "$configure_mode" = enable ] && [ "$configure_architecture" != x86_64 ]; then
    warpmetal_apparmor_policy_error=runtime_nested_private_procfs_architecture_unsupported
    return 1
  fi
  if [ ! -f "$configure_source" ] || [ -L "$configure_source" ] || \
     [ ! -f "$configure_metadata_helper" ] || [ -L "$configure_metadata_helper" ] || \
     [ ! -x "$configure_metadata_helper" ]; then
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_bundle_invalid
    return 1
  fi
  warpmetal_prepare_apparmor_durable_state "$configure_durable_state" || {
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_recovery_failed
    return 1
  }
  warpmetal_remove_apparmor_completed_state "$configure_durable_state" || {
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_recovery_failed
    return 1
  }
  warpmetal_recover_apparmor_transaction \
    "$configure_durable_state" "$configure_destination" "$configure_source" \
    "$configure_parser" "$configure_state" "$configure_metadata_helper" || {
      warpmetal_apparmor_policy_recovery_required=1
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_recovery_failed
      return 1
    }

  configure_baseline=$configure_durable_state/baseline
  configure_has_baseline=0
  if [ -e "$configure_baseline" ] || [ -L "$configure_baseline" ]; then
    warpmetal_read_apparmor_snapshot "$configure_baseline" || {
      warpmetal_apparmor_policy_recovery_required=1
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_recovery_failed
      return 1
    }
    configure_has_baseline=1
  fi

  configure_loaded_status=0
  warpmetal_read_apparmor_loaded_state "$configure_state" || configure_loaded_status=$?
  case "$configure_loaded_status" in
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

  if [ "$configure_mode" = enable ]; then
    if warpmetal_candidate_apparmor_policy_active \
      "$configure_source" "$configure_destination" "$configure_state" \
      "$configure_metadata_helper"; then
      if [ "$configure_has_baseline" -eq 0 ]; then
        warpmetal_create_empty_apparmor_baseline "$configure_durable_state" || {
          warpmetal_apparmor_policy_error=runtime_apparmor_policy_recovery_failed
          return 1
        }
      fi
      return 0
    fi
    if [ "$configure_has_baseline" -eq 1 ]; then
      configure_operation=enable-existing
    else
      configure_operation=enable-first
    fi
    warpmetal_snapshot_apparmor_policy \
      "$configure_durable_state" "$configure_operation" "$configure_destination" \
      "$configure_parser" "$configure_state" "$configure_metadata_helper" || {
        warpmetal_apparmor_policy_error=runtime_apparmor_policy_backup_failed
        return 1
      }
    if ! warpmetal_install_apparmor_policy \
      "$configure_source" "$configure_destination" \
      "$configure_durable_state/transaction/working.before" \
      "$configure_parser" "$configure_state" "$configure_metadata_helper"; then
      return 1
    fi
    warpmetal_apparmor_policy_operation=$configure_operation
    return 0
  fi

  if [ "$configure_has_baseline" -eq 0 ]; then
    if [ ! -e "$configure_destination" ] && [ ! -L "$configure_destination" ] && \
       [ "$warpmetal_apparmor_setup_loaded" -eq 0 ] && \
       [ "$warpmetal_apparmor_child_loaded" -eq 0 ]; then
      return 0
    fi
    if [ -f "$configure_destination" ] && [ ! -L "$configure_destination" ] && \
       "$configure_metadata_helper" content-equal \
         "$configure_source" "$configure_destination" >/dev/null 2>&1; then
      configure_operation=disable-legacy
    elif [ "$warpmetal_apparmor_setup_loaded" -eq 0 ] && \
         [ "$warpmetal_apparmor_child_loaded" -eq 0 ]; then
      return 0
    else
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_conflict
      return 1
    fi
  else
    configure_operation=disable-baseline
  fi

  warpmetal_snapshot_apparmor_policy \
    "$configure_durable_state" "$configure_operation" "$configure_destination" \
    "$configure_parser" "$configure_state" "$configure_metadata_helper" || {
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_backup_failed
      return 1
    }
  if [ "$configure_operation" = disable-baseline ]; then
    disable_snapshot=$configure_baseline
  else
    disable_snapshot_temporary=$configure_durable_state/transaction/disable-target
    install -d -o root -g root -m 0700 "$disable_snapshot_temporary" || {
      warpmetal_apparmor_policy_error=runtime_apparmor_policy_recovery_failed
      return 1
    }
    warpmetal_write_apparmor_state_value "$disable_snapshot_temporary/had-policy" 0 && \
      warpmetal_write_apparmor_state_value "$disable_snapshot_temporary/setup-loaded" 0 && \
      warpmetal_write_apparmor_state_value "$disable_snapshot_temporary/child-loaded" 0 || {
        warpmetal_apparmor_policy_error=runtime_apparmor_policy_recovery_failed
        return 1
      }
    disable_snapshot=$disable_snapshot_temporary
  fi
  if ! warpmetal_restore_apparmor_snapshot \
    "$disable_snapshot" "$configure_destination" "$configure_source" \
    "$configure_parser" "$configure_state" "$configure_metadata_helper"; then
    warpmetal_apparmor_policy_recovery_required=1
    warpmetal_apparmor_policy_error=runtime_apparmor_policy_recovery_failed
    return 1
  fi
  warpmetal_apparmor_policy_operation=$configure_operation
}

warpmetal_commit_apparmor_policy_operation() {
  [ -n "$warpmetal_apparmor_policy_operation" ] || return 0
  commit_root=$warpmetal_apparmor_policy_durable_state
  commit_transaction=$commit_root/transaction
  [ -d "$commit_transaction" ] && [ ! -L "$commit_transaction" ] || return 1
  rm -f -- "$commit_transaction/working.before" || return 1
  case "$warpmetal_apparmor_policy_operation" in
    enable-first)
      [ ! -e "$commit_root/baseline" ] && [ ! -L "$commit_root/baseline" ] || return 1
      mv -- "$commit_transaction" "$commit_root/baseline" || return 1
      ;;
    enable-existing|disable-legacy)
      [ ! -e "$commit_root/completed" ] && [ ! -L "$commit_root/completed" ] || return 1
      mv -- "$commit_transaction" "$commit_root/completed" || return 1
      ;;
    disable-baseline)
      [ -d "$commit_root/baseline" ] && [ ! -L "$commit_root/baseline" ] || return 1
      mv -- "$commit_root/baseline" "$commit_transaction/activation-baseline" || return 1
      [ ! -e "$commit_root/completed" ] && [ ! -L "$commit_root/completed" ] || return 1
      mv -- "$commit_transaction" "$commit_root/completed" || return 1
      ;;
    *) return 1 ;;
  esac
  warpmetal_sync_apparmor_path "$commit_root" || return 1
  warpmetal_apparmor_policy_operation=
  warpmetal_apparmor_policy_changed=0
  warpmetal_apparmor_policy_committed=1
  warpmetal_remove_apparmor_completed_state "$commit_root"
}

warpmetal_rollback_apparmor_policy() {
  if [ -n "$warpmetal_apparmor_policy_durable_state" ] && \
     [ -d "$warpmetal_apparmor_policy_durable_state/transaction" ] && \
     [ ! -L "$warpmetal_apparmor_policy_durable_state/transaction" ]; then
    if warpmetal_recover_apparmor_transaction \
      "$warpmetal_apparmor_policy_durable_state" \
      "$warpmetal_apparmor_policy_destination" \
      "$warpmetal_apparmor_policy_source" \
      "$warpmetal_apparmor_policy_parser" \
      "$warpmetal_apparmor_policy_state" \
      "$warpmetal_apparmor_policy_metadata_helper"; then
      warpmetal_apparmor_policy_operation=
      warpmetal_apparmor_policy_changed=0
      return 0
    fi
    warpmetal_apparmor_policy_recovery_required=1
    return 1
  fi
  warpmetal_rollback_apparmor_policy_legacy
}
