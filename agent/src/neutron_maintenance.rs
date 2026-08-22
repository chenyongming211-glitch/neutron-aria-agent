#[cfg(test)]
mod tests {
    use super::*;

    fn enter_request(operation_id: &str) -> MaintenanceEnterRequest {
        MaintenanceEnterRequest {
            operation_id: operation_id.to_string(),
            domains: vec!["acl".to_string()],
            reason: "planned_upgrade".to_string(),
            expected_applied_generation: 41,
            expected_desired_hash: Some("sha256:host-41".to_string()),
        }
    }

    fn convergence() -> MaintenanceConvergence {
        MaintenanceConvergence {
            applied_generation: 41,
            applied_desired_hash: Some("sha256:host-41".to_string()),
            pending_generation: None,
            managed_port_count: 2,
            ready_enforce_port_count: 2,
        }
    }

    #[test]
    fn neutron_maintenance_same_enter_is_idempotent_and_conflict_is_side_effect_free() {
        let mut machine = MaintenanceStateMachine::default();
        let request = enter_request("op-a");
        let first = machine.plan_enter(&request, &convergence(), 1_000).unwrap();
        assert_eq!(first.disposition, MaintenanceDisposition::Mutate);
        machine.commit_enter(first.next_state.unwrap());
        let baseline = machine.state().clone();

        let repeated = machine.plan_enter(&request, &convergence(), 2_000).unwrap();
        assert_eq!(repeated.disposition, MaintenanceDisposition::Idempotent);
        let mut conflicting = enter_request("op-b");
        conflicting.expected_applied_generation = 99;
        let error = machine
            .plan_enter(&conflicting, &convergence(), 3_000)
            .unwrap_err();
        assert_eq!(error.http_status, 409);
        assert_eq!(machine.state(), &baseline);
    }

    #[test]
    fn neutron_maintenance_generation_hash_and_phase_cas_mismatch_do_not_mutate_state() {
        let mut machine = MaintenanceStateMachine::default();
        let baseline = machine.state().clone();
        let mut wrong_generation = enter_request("op-a");
        wrong_generation.expected_applied_generation = 40;
        assert_eq!(
            machine
                .plan_enter(&wrong_generation, &convergence(), 1_000)
                .unwrap_err()
                .code,
            "maintenance_generation_mismatch"
        );
        let mut wrong_hash = enter_request("op-a");
        wrong_hash.expected_desired_hash = Some("sha256:wrong".to_string());
        assert_eq!(
            machine
                .plan_enter(&wrong_hash, &convergence(), 1_000)
                .unwrap_err()
                .code,
            "maintenance_desired_hash_mismatch"
        );
        assert_eq!(machine.state(), &baseline);
    }

    #[test]
    fn neutron_maintenance_dangling_enter_intent_replays_as_active_bypass() {
        let intent = MaintenanceWalRecord::enter_intent(
            enter_request("op-restart"),
            convergence(),
            1_000,
        )
        .unwrap();
        let replay = replay_maintenance_records(&[intent]).unwrap();

        assert!(replay.requires_bypass);
        assert_eq!(replay.state.operation_id.as_deref(), Some("op-restart"));
        assert_eq!(replay.state.phase, MaintenancePhase::MaintenanceBypass);
        assert!(replay.state.last_error.as_deref().unwrap().contains("intent"));
    }

    #[test]
    fn neutron_maintenance_gate_or_commit_failure_never_reports_active_success_or_clears_gate() {
        let mut machine = MaintenanceStateMachine::default();
        let plan = machine
            .plan_enter(&enter_request("op-a"), &convergence(), 1_000)
            .unwrap();
        let preparing = plan.next_state.unwrap();
        machine.record_enter_failure(preparing.clone(), "gate_readback_failed", 1_100);
        assert!(machine.state().is_active());
        assert_ne!(machine.state().phase, MaintenancePhase::Committed);
        assert!(machine.state().last_error.as_deref().unwrap().contains("gate"));

        machine.record_enter_failure(preparing, "wal_commit_failed", 1_200);
        assert!(machine.state().is_active());
        assert!(machine.state().last_error.as_deref().unwrap().contains("wal"));
    }

    #[test]
    fn neutron_maintenance_writer_fence_allows_only_matching_full_host_snapshot() {
        let state = MaintenanceState::active_for_test("op-a", 41, "sha256:host-41");
        assert!(admit_maintenance_writer(
            &state,
            MaintenanceWriter::FullHostSnapshot,
            Some("op-a")
        )
        .is_ok());
        assert_eq!(
            admit_maintenance_writer(&state, MaintenanceWriter::FullHostSnapshot, None)
                .unwrap_err()
                .code,
            "maintenance_operation_mismatch"
        );
        assert_eq!(
            admit_maintenance_writer(
                &state,
                MaintenanceWriter::FullHostSnapshot,
                Some("op-b")
            )
            .unwrap_err()
            .code,
            "maintenance_operation_mismatch"
        );
        for writer in [
            MaintenanceWriter::PortSnapshot,
            MaintenanceWriter::Delete,
            MaintenanceWriter::Periodic,
            MaintenanceWriter::Background,
            MaintenanceWriter::Direct,
        ] {
            assert_eq!(
                admit_maintenance_writer(&state, writer, Some("op-a"))
                    .unwrap_err()
                    .code,
                "maintenance_requires_full_host"
            );
        }
    }

    #[test]
    fn neutron_maintenance_exit_requires_exact_complete_convergence_and_is_idempotent() {
        let mut machine = MaintenanceStateMachine::with_state(
            MaintenanceState::active_for_test("op-a", 41, "sha256:host-41"),
        );
        let request = MaintenanceExitRequest {
            operation_id: "op-a".to_string(),
            expected_applied_generation: 41,
            expected_applied_desired_hash: Some("sha256:host-41".to_string()),
        };
        let mut incomplete = convergence();
        incomplete.ready_enforce_port_count = 1;
        assert_eq!(
            machine.plan_exit(&request, &incomplete, 2_000).unwrap_err().code,
            "maintenance_convergence_incomplete"
        );
        let plan = machine.plan_exit(&request, &convergence(), 2_000).unwrap();
        machine.commit_exit(plan.next_state.unwrap());
        assert_eq!(machine.state().phase, MaintenancePhase::Committed);
        assert_eq!(
            machine
                .plan_exit(&request, &convergence(), 3_000)
                .unwrap()
                .disposition,
            MaintenanceDisposition::Idempotent
        );
    }

    #[test]
    fn neutron_maintenance_abort_and_restart_remain_bypassed_without_convergence() {
        let mut machine = MaintenanceStateMachine::with_state(
            MaintenanceState::active_for_test("op-a", 41, "sha256:host-41"),
        );
        let request = MaintenanceAbortRequest {
            operation_id: "op-a".to_string(),
            expected_phase: MaintenancePhase::MaintenanceBypass,
            error: Some("candidate_failed".to_string()),
        };
        let mut incomplete = convergence();
        incomplete.pending_generation = Some(42);
        let next = machine.plan_abort(&request, &incomplete, 2_000).unwrap();
        machine.commit_abort(next.next_state.unwrap());
        assert!(machine.state().is_active());
        let replay = replay_maintenance_records(&[
            MaintenanceWalRecord::abort_commit(machine.state().clone()),
        ])
        .unwrap();
        assert!(replay.requires_bypass);
    }

    #[test]
    fn neutron_maintenance_records_are_bounded_typed_and_reject_duplicate_unknown_or_oversized() {
        let request = enter_request("op-a");
        let intent = MaintenanceWalRecord::enter_intent(request, convergence(), 1_000).unwrap();
        assert!(replay_maintenance_records(&[intent.clone(), intent])
            .unwrap_err()
            .contains("duplicate"));
        assert!(decode_maintenance_record(br#"{"schema_version":1,"kind":"unknown"}"#)
            .unwrap_err()
            .contains("unknown"));
        assert!(decode_maintenance_record(&vec![b'x'; MAINTENANCE_WAL_RECORD_MAX_BYTES + 1])
            .unwrap_err()
            .contains("oversized"));
        let nested = br#"{"schema_version":1,"kind":"enter_intent","state":{"operation_id":{"secret":"leak"}}}"#;
        assert!(decode_maintenance_record(nested).is_err());
    }

    #[test]
    fn neutron_maintenance_status_is_bounded_and_contains_no_policy_or_secret_fields() {
        let state = MaintenanceState::active_for_test("op-a", 41, "sha256:host-41");
        let encoded = serde_json::to_value(&state).unwrap();
        assert!(encoded.get("policy").is_none());
        assert!(encoded.get("token").is_none());
        assert!(encoded.get("secret").is_none());
        assert!(encoded["active_domains"].as_array().unwrap().len() <= 4);
    }

    #[test]
    fn neutron_maintenance_admin_socket_policy_is_exact_and_rejects_symlinks_or_non_sockets() {
        assert_eq!(ADMIN_SOCKET_PATH, "/run/aria/aria-admin.sock");
        let valid = AdminSocketFacts {
            parent_is_directory: true,
            parent_is_symlink: false,
            parent_uid: 0,
            parent_gid: 0,
            socket_is_socket: true,
            socket_is_symlink: false,
            socket_uid: 0,
            socket_gid: 0,
            socket_mode: 0o600,
        };
        validate_admin_socket_facts(&valid).unwrap();

        let mut symlink = valid;
        symlink.socket_is_symlink = true;
        assert!(validate_admin_socket_facts(&symlink).is_err());
        let mut non_socket = valid;
        non_socket.socket_is_socket = false;
        assert!(validate_admin_socket_facts(&non_socket).is_err());
        let mut public = valid;
        public.socket_mode = 0o660;
        assert!(validate_admin_socket_facts(&public).is_err());
        let mut non_root = valid;
        non_root.socket_uid = 1000;
        assert!(validate_admin_socket_facts(&non_root).is_err());
    }

    #[test]
    fn neutron_maintenance_admin_route_inventory_is_separate_and_complete() {
        assert_eq!(
            admin_route_specs(),
            &[
                ("POST", "/api/v1/admin/maintenance/enter"),
                ("GET", "/api/v1/admin/maintenance"),
                ("POST", "/api/v1/admin/maintenance/exit"),
                ("POST", "/api/v1/admin/maintenance/abort"),
            ]
        );
        for (_, path) in admin_route_specs() {
            assert!(!neutron_route_specs().iter().any(|(_, route)| route == path));
            assert!(!tcp_route_specs().iter().any(|(_, route)| route == path));
        }
    }
}
