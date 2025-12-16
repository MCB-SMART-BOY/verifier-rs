// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::btf::integration

use bpf_verifier::btf::integration::*;

use super::*;

    #[test]
    fn test_source_location() {
        let loc = SourceLocation::new("test.c", 10, 5)
            .with_function("foo");
        
        assert_eq!(loc.file, "test.c");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, 5);
        assert_eq!(loc.function, Some("foo".to_string()));
        
        let formatted = loc.format_for_error();
        assert!(formatted.contains("test.c"));
        assert!(formatted.contains("10"));
        assert!(formatted.contains("foo"));
    }

    #[test]
    fn test_line_info_db() {
        let mut db = LineInfoDb::new();
        
        db.add_string(0, "main.c");
        db.add_string(8, "helper.c");
        
        assert_eq!(db.get_string(0), Some("main.c"));
        assert_eq!(db.get_string(8), Some("helper.c"));
        assert_eq!(db.get_string(100), None);
    }

    #[test]
    fn test_btf_context_default() {
        let ctx = BtfContext::new();
        assert!(!ctx.btf_enabled);
        assert!(ctx.prog_btf.is_none());
        assert!(ctx.kernel_btf.is_none());
    }

    #[test]
    fn test_reg_btf_info() {
        let info = RegBtfInfo::none();
        assert!(!info.has_btf());
        assert!(!info.is_acquired());
        
        let info = RegBtfInfo::with_type(42);
        assert!(info.has_btf());
        assert_eq!(info.btf_id, 42);
        
        let info = RegBtfInfo::acquired(42, 1);
        assert!(info.has_btf());
        assert!(info.is_acquired());
        assert!(info.trusted);
    }

    #[test]
    fn test_btf_access_result() {
        let result = BtfAccessResult {
            valid: true,
            field_type_id: 10,
            permissions: BtfPermissions::default(),
        };
        assert!(result.valid);
        assert_eq!(result.field_type_id, 10);
    }

    #[test]
    fn test_kfunc_validation() {
        let result = KfuncValidation {
            valid: true,
            ret_type_id: 5,
            acquires_ref: true,
            releases_ref: false,
            release_arg_idx: None,
        };
        assert!(result.valid);
        assert!(result.acquires_ref);
        assert!(!result.releases_ref);
    }
