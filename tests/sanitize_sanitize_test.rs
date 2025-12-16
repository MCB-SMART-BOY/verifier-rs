// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::sanitize::sanitize

use bpf_verifier::sanitize::sanitize::*;

use super::*;

    #[test]
    fn test_sanitize_needed() {
        assert!(sanitize_needed(false)); // Unprivileged
        assert!(!sanitize_needed(true)); // Privileged
    }

    #[test]
    fn test_error_recoverable() {
        assert!(error_recoverable_with_nospec(
            &VerifierError::PermissionDenied("test".into())
        ));
        assert!(error_recoverable_with_nospec(
            &VerifierError::InvalidMemoryAccess("test".into())
        ));
        assert!(!error_recoverable_with_nospec(
            &VerifierError::InvalidInstruction(0)
        ));
    }

    #[test]
    fn test_can_skip_sanitation() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        
        // Scalar destination - can skip
        assert!(can_skip_alu_sanitation(&reg, None));
        
        // Pointer destination - cannot skip with unknown source
        reg.reg_type = BpfRegType::PtrToStack;
        assert!(!can_skip_alu_sanitation(&reg, None));
        
        // Pointer with const source - can skip
        let mut src = BpfRegState::default();
        src.reg_type = BpfRegType::ScalarValue;
        src.mark_known(100);
        assert!(can_skip_alu_sanitation(&reg, Some(&src)));
    }

    #[test]
    fn test_ptr_limit_stack() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -16;
        
        let limit = retrieve_ptr_limit(&reg, 0, false).unwrap();
        assert_eq!(limit.umax, 16);
        assert!(limit.is_exact);
    }

    #[test]
    fn test_insn_aux_data() {
        let mut aux = InsnAuxData::new();
        assert!(!aux.seen);
        assert!(!aux.needs_nospec_barrier);
        
        sanitize_mark_insn_seen(&mut aux, true);
        assert!(aux.seen);
        assert!(aux.needs_nospec_barrier);
    }

    #[test]
    fn test_sanitize_state() {
        let mut state = SanitizeState::None;
        assert_eq!(state, SanitizeState::None);
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToMapValue;
        
        update_alu_sanitation_state(&mut state, &reg, None);
        assert_eq!(state, SanitizeState::NeedsBarrier);
    }

    // ========================================================================
    // Enhanced Spectre v1 Tests
    // ========================================================================

    #[test]
    fn test_speculative_path_tracker() {
        let mut tracker = SpeculativePathTracker::new();
        
        assert!(!tracker.is_speculative());
        assert_eq!(tracker.depth(), 0);
        
        // Enter a branch
        tracker.enter_branch(10, true);
        assert!(tracker.is_speculative());
        assert_eq!(tracker.depth(), 1);
        assert_eq!(tracker.current_branch(), Some((10, true)));
        
        // Record instructions
        tracker.record_insn(11);
        tracker.record_insn(12);
        assert!(tracker.in_speculation_window(11));
        assert!(tracker.in_speculation_window(12));
        
        // Enter nested branch
        tracker.enter_branch(13, false);
        assert_eq!(tracker.depth(), 2);
        
        // Exit one branch
        tracker.exit_branch();
        assert_eq!(tracker.depth(), 1);
        
        // Exit all
        tracker.exit_branch();
        assert!(!tracker.is_speculative());
    }

    #[test]
    fn test_spectre_v1_taint() {
        assert!(!SpectreV1Taint::Clean.is_tainted());
        assert!(SpectreV1Taint::Tainted.is_tainted());
        assert!(SpectreV1Taint::Derived.is_tainted());
        assert!(SpectreV1Taint::SpeculativeTainted.is_tainted());
    }

    #[test]
    fn test_spectre_v1_taint_propagation() {
        let clean = SpectreV1Taint::Clean;
        let tainted = SpectreV1Taint::Tainted;
        let derived = SpectreV1Taint::Derived;
        
        // Clean + Clean = Clean
        assert_eq!(clean.propagate(&clean), SpectreV1Taint::Clean);
        
        // Tainted + anything = Tainted
        assert_eq!(tainted.propagate(&clean), SpectreV1Taint::Tainted);
        assert_eq!(clean.propagate(&tainted), SpectreV1Taint::Tainted);
        
        // Derived + Derived = Derived
        assert_eq!(derived.propagate(&derived), SpectreV1Taint::Derived);
    }

    #[test]
    fn test_spectre_v1_taint_tracker() {
        let mut tracker = SpectreV1TaintTracker::new();
        
        // Initially clean
        assert!(!tracker.is_tainted(0));
        
        // Taint from input
        tracker.taint_from_input(1, 5);
        assert!(tracker.is_tainted(1));
        assert_eq!(tracker.get_taint(1), SpectreV1Taint::Tainted);
        
        // Propagate taint
        tracker.propagate_alu(2, 1);
        assert!(tracker.is_tainted(2));
        
        // Clear taint
        tracker.clear_taint(1);
        assert!(!tracker.is_tainted(1));
        
        // Mark speculative
        tracker.taint_from_input(3, 10);
        tracker.mark_speculative_taint(3, 15);
        assert_eq!(tracker.get_taint(3), SpectreV1Taint::SpeculativeTainted);
    }

    #[test]
    fn test_spectre_v1_analyzer_creation() {
        let config = SpectreConfig::default();
        let analyzer = SpectreV1Analyzer::new(config);
        
        assert!(analyzer.get_gadgets().is_empty());
    }

    #[test]
    fn test_spectre_v1_gadget_types() {
        // Test all gadget types exist
        let _bounds = SpectreV1GadgetType::BoundsCheckBypass;
        let _confusion = SpectreV1GadgetType::TypeConfusion;
        let _ptr_leak = SpectreV1GadgetType::PointerLeak;
        let _data_leak = SpectreV1GadgetType::DataLeak;
        let _hijack = SpectreV1GadgetType::ControlFlowHijack;
    }

    #[test]
    fn test_spectre_v1_summary() {
        let summary = SpectreV1Summary::default();
        
        assert_eq!(summary.total_gadgets, 0);
        assert_eq!(summary.bounds_bypass, 0);
        assert_eq!(summary.data_leaks, 0);
        assert_eq!(summary.pointer_leaks, 0);
    }

    #[test]
    fn test_spectre_v1_analyzer_external_input() {
        let config = SpectreConfig::default();
        let mut analyzer = SpectreV1Analyzer::new(config);
        
        // Mark external input
        analyzer.mark_external_input(2, 0);
        
        // Check it's tracked
        assert!(analyzer.taint.is_tainted(2));
    }

    #[test]
    fn test_spectre_v1_analyzer_sanitization() {
        let config = SpectreConfig::default();
        let mut analyzer = SpectreV1Analyzer::new(config);
        
        // Taint then sanitize
        analyzer.mark_external_input(3, 0);
        assert!(analyzer.taint.is_tainted(3));
        
        analyzer.apply_sanitization(3);
        assert!(!analyzer.taint.is_tainted(3));
    }

    #[test]
    fn test_speculative_path_window_limit() {
        let mut tracker = SpeculativePathTracker::with_window(3);
        
        tracker.enter_branch(0, true);
        
        // Add more than window size
        tracker.record_insn(1);
        tracker.record_insn(2);
        tracker.record_insn(3);
        tracker.record_insn(4); // Should push out insn 1
        
        assert!(!tracker.in_speculation_window(1));
        assert!(tracker.in_speculation_window(2));
        assert!(tracker.in_speculation_window(3));
        assert!(tracker.in_speculation_window(4));
    }

    #[test]
    fn test_spectre_config_default() {
        let config = SpectreConfig::default();
        
        assert!(config.mitigate_v1);
        assert!(config.mitigate_v2);
        assert!(config.mitigate_v4);
        assert!(!config.aggressive);
        assert!(config.allow_jit_bypass);
    }
