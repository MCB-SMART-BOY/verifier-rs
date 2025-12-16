// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::verifier::result

use bpf_verifier::prelude::*;
use bpf_verifier::verifier::result::*;


    #[test]
    fn test_success_outcome() {
        let builder = ResultBuilder::new();
        let outcome = builder.success();
        
        assert!(outcome.is_success());
        assert!(!outcome.is_failure());
        assert!(outcome.error().is_none());
    }

    #[test]
    fn test_failure_outcome() {
        let builder = ResultBuilder::new();
        let outcome = builder.failure(
            VerifierError::UninitializedRegister(5),
            10,
        );
        
        assert!(outcome.is_failure());
        assert!(outcome.error().is_some());
        
        if let VerificationOutcome::Failure(info) = &outcome {
            assert_eq!(info.insn_idx, 10);
            assert!(!info.suggestions.is_empty()); // Should have suggestions
        }
    }

    #[test]
    fn test_failure_info_builder() {
        let info = FailureInfo::new(VerifierError::DivisionByZero, 5)
            .with_context(ErrorContext::AluOp {
                op: "div",
                dst_reg: 0,
                src: AluSource::Register(1),
            })
            .with_suggestion("Check divisor is non-zero")
            .with_suggestion("Use AND to mask divisor");
        
        assert_eq!(info.insn_idx, 5);
        assert_eq!(info.suggestions.len(), 2);
    }

    #[test]
    fn test_aborted_outcome() {
        let builder = ResultBuilder::new();
        let outcome = builder.aborted(
            AbortReason::ComplexityLimit { limit: 1000000, reached: 1000001 },
            VerificationProgress {
                insns_verified: 500,
                branches_explored: 100,
                coverage_percent: 50,
            },
        );
        
        if let VerificationOutcome::Aborted(info) = &outcome {
            assert!(matches!(info.reason, AbortReason::ComplexityLimit { .. }));
            assert_eq!(info.progress.insns_verified, 500);
        } else {
            panic!("Expected Aborted outcome");
        }
    }

    #[test]
    fn test_result_builder_properties() {
        let mut builder = ResultBuilder::new();
        
        builder.record_helper(1); // map_lookup_elem
        builder.record_helper(2); // map_update_elem
        builder.record_map(BpfMapType::Hash);
        
        builder.set_property(|p| {
            p.uses_packet_access = true;
            p.max_stack_depth = 128;
        });
        
        let outcome = builder.success();
        
        if let VerificationOutcome::Success(info) = outcome {
            assert!(info.properties.uses_helpers);
            assert!(info.properties.uses_maps);
            assert!(info.properties.uses_packet_access);
            assert_eq!(info.properties.helpers_used.len(), 2);
            assert_eq!(info.properties.max_stack_depth, 128);
        }
    }

    #[test]
    fn test_warning() {
        let warning = VerifierWarning {
            code: WarningCode::UnreachableCode,
            insn_idx: Some(42),
            message: "Instructions 42-50 are unreachable".into(),
        };
        
        assert_eq!(warning.insn_idx, Some(42));
        assert_eq!(warning.code, WarningCode::UnreachableCode);
    }

    #[test]
    fn test_display_success() {
        let mut builder = ResultBuilder::new();
        builder.stats.insns_processed = 100;
        builder.stats.total_states = 50;
        builder.stats.states_pruned = 20;
        
        let outcome = builder.success();
        let display = format!("{}", outcome);
        
        assert!(display.contains("PASSED"));
        assert!(display.contains("100"));
    }

    #[test]
    fn test_display_failure() {
        let builder = ResultBuilder::new();
        let outcome = builder.failure(
            VerifierError::InvalidMemoryAccess("packet bounds".into()),
            15,
        );
        
        let display = format!("{}", outcome);
        
        assert!(display.contains("FAILED"));
        assert!(display.contains("15"));
        assert!(display.contains("Suggestions"));
    }

    #[test]
    fn test_error_suggestions() {
        let mut info = FailureInfo::new(VerifierError::BackEdgeDetected, 0);
        add_error_suggestions(&mut info);
        
        assert!(!info.suggestions.is_empty());
        assert!(info.suggestions.iter().any(|s| s.contains("bpf_loop")));
    }

    #[test]
    fn test_related_error() {
        let related = RelatedError {
            error: VerifierError::UninitializedRegister(3),
            insn_idx: 5,
            description: "R3 may be uninitialized on this path".into(),
        };
        
        let info = FailureInfo::new(VerifierError::UninitializedRegister(3), 10)
            .with_related(related);
        
        assert_eq!(info.related.len(), 1);
        assert_eq!(info.related[0].insn_idx, 5);
    }
