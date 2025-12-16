// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::special::rbtree

use bpf_verifier::special::rbtree::*;


    #[test]
    fn test_graph_root_creation() {
        let root = GraphRoot::rbtree(1, 2, 16, 0);
        assert_eq!(root.graph_type, GraphType::Rbtree);
        assert_eq!(root.btf_id, 1);
        assert_eq!(root.value_btf_id, 2);
        assert_eq!(root.node_offset, 16);
    }

    #[test]
    fn test_rbtree_kfunc_detection() {
        assert!(is_rbtree_kfunc(rbtree_kfuncs::RBTREE_ADD_IMPL));
        assert!(is_rbtree_kfunc(rbtree_kfuncs::RBTREE_REMOVE));
        assert!(!is_rbtree_kfunc(0));
    }

    #[test]
    fn test_graph_node_tracker() {
        let mut tracker = GraphNodeTracker::new();
        
        // Allocate node
        let id = tracker.alloc_node(GraphType::Rbtree, 100, 16);
        assert!(tracker.get_node(id).is_some());
        
        // Insert into tree
        assert!(tracker.insert_node(id).is_ok());
        assert_eq!(tracker.get_node(id).unwrap().ownership, NodeOwnership::InGraph);
        
        // Remove from tree
        assert!(tracker.remove_node(id).is_ok());
        assert_eq!(tracker.get_node(id).unwrap().ownership, NodeOwnership::Owned);
        
        // Release
        assert!(tracker.release_node(id).is_ok());
        assert!(tracker.get_node(id).is_none());
    }

    #[test]
    fn test_rbtree_callback_state() {
        let mut state = RbtreeCallbackState::new();
        assert!(!state.in_rbtree_cb);
        
        let root = GraphRoot::rbtree(1, 2, 16, 0);
        state.enter_callback(rbtree_kfuncs::RBTREE_ADD_IMPL, root);
        
        assert!(state.in_rbtree_cb);
        assert!(in_rbtree_lock_required_cb(&state));
        
        state.exit_callback();
        assert!(!state.in_rbtree_cb);
    }

    #[test]
    fn test_leak_detection() {
        let mut tracker = GraphNodeTracker::new();
        
        // Allocate without release - should leak
        let id = tracker.alloc_node(GraphType::Rbtree, 100, 16);
        assert!(tracker.check_no_leaks().is_err());
        
        // Insert into tree - no longer owned, no leak
        tracker.insert_node(id).unwrap();
        assert!(tracker.check_no_leaks().is_ok());
    }

    #[test]
    fn test_container_of_offset() {
        // Node at offset 16 in container
        let result = container_of_offset(16, 16);
        assert_eq!(result, 0); // Points to container start
        
        // Node pointer with offset 24, node field at offset 16
        let result = container_of_offset(24, 16);
        assert_eq!(result, 8); // Points 8 bytes into container
    }

    #[test]
    fn test_list_kfunc_detection() {
        assert!(is_list_kfunc(list_kfuncs::LIST_PUSH_FRONT));
        assert!(is_list_kfunc(list_kfuncs::LIST_POP_BACK));
        assert!(!is_list_kfunc(rbtree_kfuncs::RBTREE_ADD_IMPL));
        assert!(is_graph_kfunc(list_kfuncs::LIST_PUSH_FRONT));
        assert!(is_graph_kfunc(rbtree_kfuncs::RBTREE_ADD_IMPL));
    }

    #[test]
    fn test_field_records() {
        let mut records = BpfFieldRecords::new();
        
        // Add rbtree root record
        records.add_record(BpfFieldRecord {
            field_type: BpfFieldType::RbRoot,
            offset: 0,
            size: 8,
            container_btf_id: 100,
            graph_value_btf_id: Some(200),
            graph_node_offset: Some(16),
        });
        
        // Add matching node record
        records.add_record(BpfFieldRecord {
            field_type: BpfFieldType::RbNode,
            offset: 16,
            size: 24,
            container_btf_id: 200,
            graph_value_btf_id: Some(200),
            graph_node_offset: None,
        });
        
        // Get record by offset
        let record = records.get_record(100, 0).unwrap();
        assert_eq!(record.field_type, BpfFieldType::RbRoot);
        assert!(record.is_graph_root());
        assert!(!record.is_graph_node());
        
        // Get records for type
        let type_records = records.get_records_for_type(100);
        assert_eq!(type_records.len(), 1);
        
        // Find matching root for node
        let node_record = records.get_record(200, 16).unwrap();
        let matching_root = records.find_matching_root(node_record);
        assert!(matching_root.is_some());
        assert_eq!(matching_root.unwrap().offset, 0);
    }

    #[test]
    fn test_graph_op_safety() {
        let mut tracker = GraphNodeTracker::new();
        
        // Allocate owned node
        let id = tracker.alloc_node(GraphType::Rbtree, 100, 16);
        
        // Insert should succeed for owned node
        assert!(verify_graph_op_safety(&tracker, id, GraphOpType::Insert).is_ok());
        
        // Actually insert the node
        tracker.insert_node(id).unwrap();
        
        // Insert should fail for node already in graph
        assert!(verify_graph_op_safety(&tracker, id, GraphOpType::Insert).is_err());
        
        // Remove should succeed for node in graph
        assert!(verify_graph_op_safety(&tracker, id, GraphOpType::Remove).is_ok());
        
        // Traverse is always ok
        assert!(verify_graph_op_safety(&tracker, id, GraphOpType::Traverse).is_ok());
    }

    #[test]
    fn test_kfunc_to_graph_op() {
        assert_eq!(
            kfunc_to_graph_op(rbtree_kfuncs::RBTREE_ADD_IMPL),
            Some(GraphOpType::Insert)
        );
        assert_eq!(
            kfunc_to_graph_op(rbtree_kfuncs::RBTREE_REMOVE),
            Some(GraphOpType::Remove)
        );
        assert_eq!(
            kfunc_to_graph_op(rbtree_kfuncs::RBTREE_FIRST),
            Some(GraphOpType::Traverse)
        );
        assert_eq!(
            kfunc_to_graph_op(list_kfuncs::LIST_PUSH_FRONT),
            Some(GraphOpType::Insert)
        );
        assert_eq!(
            kfunc_to_graph_op(list_kfuncs::LIST_POP_FRONT),
            Some(GraphOpType::Remove)
        );
        assert_eq!(kfunc_to_graph_op(0), None);
    }
