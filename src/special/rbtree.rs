//! Rbtree and graph node tracking
//!
//! This module implements verification for BPF rbtree operations
//! and graph data structure nodes (bpf_rb_root, bpf_rb_node, bpf_list_head, etc.)

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::core::error::{Result, VerifierError};

#[cfg(not(feature = "std"))]
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

// ============================================================================
// Graph Root Types
// ============================================================================

/// Types of graph data structures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphType {
    /// Red-black tree (bpf_rb_root/bpf_rb_node)
    Rbtree,
    /// Linked list (bpf_list_head/bpf_list_node)
    List,
}

/// Graph root field information
#[derive(Debug, Clone)]
pub struct GraphRoot {
    /// Type of graph structure
    pub graph_type: GraphType,
    /// BTF ID of the containing struct
    pub btf_id: u32,
    /// BTF ID of the value type
    pub value_btf_id: u32,
    /// Offset of the node field within value
    pub node_offset: i32,
    /// BTF reference
    pub btf: u32,
}

impl GraphRoot {
    /// Create a new rbtree root
    pub fn rbtree(btf_id: u32, value_btf_id: u32, node_offset: i32, btf: u32) -> Self {
        Self {
            graph_type: GraphType::Rbtree,
            btf_id,
            value_btf_id,
            node_offset,
            btf,
        }
    }

    /// Create a new list root
    pub fn list(btf_id: u32, value_btf_id: u32, node_offset: i32, btf: u32) -> Self {
        Self {
            graph_type: GraphType::List,
            btf_id,
            value_btf_id,
            node_offset,
            btf,
        }
    }
}

// ============================================================================
// Rbtree Kfunc IDs
// ============================================================================

/// Rbtree kfunc identifiers
pub mod rbtree_kfuncs {
    /// bpf_rbtree_add_impl
    pub const RBTREE_ADD_IMPL: u32 = 0x4001;
    /// bpf_rbtree_remove
    pub const RBTREE_REMOVE: u32 = 0x4002;
    /// bpf_rbtree_first
    pub const RBTREE_FIRST: u32 = 0x4003;
    /// bpf_rbtree_root (get root from node)
    pub const RBTREE_ROOT: u32 = 0x4004;
    /// bpf_rbtree_left
    pub const RBTREE_LEFT: u32 = 0x4005;
    /// bpf_rbtree_right
    pub const RBTREE_RIGHT: u32 = 0x4006;
}

/// Check if kfunc is an rbtree operation
pub fn is_rbtree_kfunc(kfunc_id: u32) -> bool {
    matches!(
        kfunc_id,
        rbtree_kfuncs::RBTREE_ADD_IMPL
            | rbtree_kfuncs::RBTREE_REMOVE
            | rbtree_kfuncs::RBTREE_FIRST
            | rbtree_kfuncs::RBTREE_ROOT
            | rbtree_kfuncs::RBTREE_LEFT
            | rbtree_kfuncs::RBTREE_RIGHT
    )
}

/// Check if kfunc requires rbtree lock to be held
pub fn is_rbtree_lock_required_kfunc(kfunc_id: u32) -> bool {
    matches!(
        kfunc_id,
        rbtree_kfuncs::RBTREE_ADD_IMPL
            | rbtree_kfuncs::RBTREE_REMOVE
            | rbtree_kfuncs::RBTREE_FIRST
    )
}

// ============================================================================
// Graph Node State
// ============================================================================

/// Ownership state for graph nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeOwnership {
    /// Node is owned (can be inserted/removed)
    Owned,
    /// Node is non-owning reference (borrowed from tree)
    NonOwning,
    /// Node is in tree (not directly owned)
    InGraph,
}

/// State for a graph node pointer
#[derive(Debug, Clone)]
pub struct GraphNodeState {
    /// Type of graph this node belongs to
    pub graph_type: GraphType,
    /// Ownership state
    pub ownership: NodeOwnership,
    /// Reference ID for tracking
    pub ref_obj_id: u32,
    /// BTF ID of the node type
    pub btf_id: u32,
    /// Offset within containing struct
    pub node_offset: i32,
}

/// Mark register as graph node
pub fn mark_reg_graph_node(
    reg: &mut BpfRegState,
    graph_root: &GraphRoot,
) {
    use crate::state::reg_state::BtfInfo;
    
    reg.mark_known(0);
    reg.reg_type = BpfRegType::PtrToBtfId;
    reg.btf_info = Some(BtfInfo::new(graph_root.value_btf_id));
    reg.off = graph_root.node_offset;
    // MEM_ALLOC flag would be set here in full implementation
}

/// Set non-owning reference on register
pub fn ref_set_non_owning(reg: &mut BpfRegState) {
    // Mark as non-owning reference
    // In full implementation, this updates type flags
    reg.ref_obj_id = 0; // Non-owning refs don't have ref_obj_id
}

// ============================================================================
// Rbtree Callback State
// ============================================================================

/// State for rbtree comparison callback
#[derive(Debug, Clone)]
pub struct RbtreeCallbackState {
    /// Whether we're in an rbtree callback
    pub in_rbtree_cb: bool,
    /// Kfunc that triggered the callback
    pub kfunc_btf_id: u32,
    /// Graph root for the callback
    pub graph_root: Option<GraphRoot>,
}

impl Default for RbtreeCallbackState {
    fn default() -> Self {
        Self::new()
    }
}

impl RbtreeCallbackState {
    /// Create new callback state
    pub fn new() -> Self {
        Self {
            in_rbtree_cb: false,
            kfunc_btf_id: 0,
            graph_root: None,
        }
    }

    /// Enter rbtree callback
    pub fn enter_callback(&mut self, kfunc_btf_id: u32, graph_root: GraphRoot) {
        self.in_rbtree_cb = true;
        self.kfunc_btf_id = kfunc_btf_id;
        self.graph_root = Some(graph_root);
    }

    /// Exit rbtree callback
    pub fn exit_callback(&mut self) {
        self.in_rbtree_cb = false;
        self.kfunc_btf_id = 0;
        self.graph_root = None;
    }
}

/// Check if we're in an rbtree lock-required callback
pub fn in_rbtree_lock_required_cb(cb_state: &RbtreeCallbackState) -> bool {
    cb_state.in_rbtree_cb && is_rbtree_lock_required_kfunc(cb_state.kfunc_btf_id)
}

// ============================================================================
// Rbtree Add Callback Setup
// ============================================================================

/// Set up state for rbtree_add comparison callback
/// 
/// bpf_rbtree_add_impl(root, node, less_cb) takes a comparison callback
/// that receives two bpf_rb_node pointers to compare
pub fn set_rbtree_add_callback_state(
    callee_regs: &mut [BpfRegState],
    graph_root: &GraphRoot,
) -> Result<()> {
    if callee_regs.len() < 6 {
        return Err(VerifierError::Internal("not enough registers".into()));
    }

    // R1 = first node (non-owning reference)
    mark_reg_graph_node(&mut callee_regs[1], graph_root);
    ref_set_non_owning(&mut callee_regs[1]);

    // R2 = second node (non-owning reference)
    mark_reg_graph_node(&mut callee_regs[2], graph_root);
    ref_set_non_owning(&mut callee_regs[2]);

    // R3-R5 not used
    for i in 3..=5 {
        callee_regs[i].mark_not_init(false);
    }

    Ok(())
}

// ============================================================================
// Rbtree Operation Validation
// ============================================================================

/// Validate rbtree root argument
pub fn validate_rbtree_root_arg(
    reg: &BpfRegState,
    expected_btf_id: Option<u32>,
) -> Result<()> {
    // Must be a pointer to bpf_rb_root
    if reg.reg_type != BpfRegType::PtrToBtfId && reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to bpf_rb_root".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    if let Some(expected) = expected_btf_id {
        if reg.btf_id() != expected {
            return Err(VerifierError::TypeMismatch {
                expected: format!("btf_id {}", expected),
                got: format!("btf_id {}", reg.btf_id()),
            });
        }
    }

    Ok(())
}

/// Validate rbtree node argument
pub fn validate_rbtree_node_arg(
    reg: &BpfRegState,
    must_be_owned: bool,
) -> Result<()> {
    // Must be a pointer to struct containing bpf_rb_node
    if reg.reg_type != BpfRegType::PtrToBtfId {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to bpf_rb_node".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    // Check ownership if required
    if must_be_owned && reg.ref_obj_id == 0 {
        return Err(VerifierError::InvalidState(
            "rbtree_add requires owned node".into()
        ));
    }

    Ok(())
}

/// Process rbtree_add return
pub fn process_rbtree_add_return(
    ret_reg: &mut BpfRegState,
    node_reg: &BpfRegState,
) {
    // bpf_rbtree_add returns void, but the node is now in the tree
    // The node reference is consumed
    ret_reg.mark_not_init(false);
    // The original node_reg should have its ref_obj_id released
    let _ = node_reg; // Used for reference tracking
}

/// Process rbtree_remove return
pub fn process_rbtree_remove_return(
    ret_reg: &mut BpfRegState,
    graph_root: &GraphRoot,
    ref_obj_id: u32,
) {
    // bpf_rbtree_remove returns owned node pointer (or NULL)
    mark_reg_graph_node(ret_reg, graph_root);
    ret_reg.ref_obj_id = ref_obj_id;
    // MEM_RCU and PTR_MAYBE_NULL flags would be set
}

/// Process rbtree_first return
pub fn process_rbtree_first_return(
    ret_reg: &mut BpfRegState,
    graph_root: &GraphRoot,
) {
    // bpf_rbtree_first returns non-owning reference (or NULL)
    mark_reg_graph_node(ret_reg, graph_root);
    ref_set_non_owning(ret_reg);
    // PTR_MAYBE_NULL flag would be set
}

// ============================================================================
// Graph Node Tracker
// ============================================================================

/// Tracks graph nodes across verification
#[derive(Debug, Clone, Default)]
pub struct GraphNodeTracker {
    /// Registered graph roots by map_uid
    roots: HashMap<u32, GraphRoot>,
    /// Active nodes by ref_obj_id
    nodes: HashMap<u32, GraphNodeState>,
    /// Next node ID
    next_id: u32,
}

impl GraphNodeTracker {
    /// Create new tracker
    pub fn new() -> Self {
        Self {
            roots: HashMap::new(),
            nodes: HashMap::new(),
            next_id: 1,
        }
    }

    /// Register a graph root
    pub fn register_root(&mut self, map_uid: u32, root: GraphRoot) {
        self.roots.insert(map_uid, root);
    }

    /// Get graph root by map_uid
    pub fn get_root(&self, map_uid: u32) -> Option<&GraphRoot> {
        self.roots.get(&map_uid)
    }

    /// Allocate a new owned node
    pub fn alloc_node(
        &mut self,
        graph_type: GraphType,
        btf_id: u32,
        node_offset: i32,
    ) -> u32 {
        let id = self.next_id;
        self.next_id += 1;

        self.nodes.insert(id, GraphNodeState {
            graph_type,
            ownership: NodeOwnership::Owned,
            ref_obj_id: id,
            btf_id,
            node_offset,
        });

        id
    }

    /// Get node state by ref_obj_id
    pub fn get_node(&self, ref_obj_id: u32) -> Option<&GraphNodeState> {
        self.nodes.get(&ref_obj_id)
    }

    /// Transfer node ownership to graph
    pub fn insert_node(&mut self, ref_obj_id: u32) -> Result<()> {
        if let Some(node) = self.nodes.get_mut(&ref_obj_id) {
            if node.ownership != NodeOwnership::Owned {
                return Err(VerifierError::InvalidState(
                    "can only insert owned nodes".into()
                ));
            }
            node.ownership = NodeOwnership::InGraph;
            Ok(())
        } else {
            Err(VerifierError::InvalidState(
                "node not found".into()
            ))
        }
    }

    /// Remove node from graph (returns ownership)
    pub fn remove_node(&mut self, ref_obj_id: u32) -> Result<()> {
        if let Some(node) = self.nodes.get_mut(&ref_obj_id) {
            if node.ownership != NodeOwnership::InGraph {
                return Err(VerifierError::InvalidState(
                    "node not in graph".into()
                ));
            }
            node.ownership = NodeOwnership::Owned;
            Ok(())
        } else {
            Err(VerifierError::InvalidState(
                "node not found".into()
            ))
        }
    }

    /// Release an owned node
    pub fn release_node(&mut self, ref_obj_id: u32) -> Result<()> {
        if let Some(node) = self.nodes.remove(&ref_obj_id) {
            if node.ownership != NodeOwnership::Owned {
                return Err(VerifierError::InvalidState(
                    "can only release owned nodes".into()
                ));
            }
            Ok(())
        } else {
            Err(VerifierError::InvalidState(
                "node not found".into()
            ))
        }
    }

    /// Check for leaked nodes at exit
    pub fn check_no_leaks(&self) -> Result<()> {
        for (id, node) in &self.nodes {
            if node.ownership == NodeOwnership::Owned {
                return Err(VerifierError::UnreleasedReference(*id));
            }
        }
        Ok(())
    }
}

// ============================================================================
// List Operations (similar to rbtree)
// ============================================================================

/// List kfunc identifiers
pub mod list_kfuncs {
    /// bpf_list_push_front
    pub const LIST_PUSH_FRONT: u32 = 0x4101;
    /// bpf_list_push_back
    pub const LIST_PUSH_BACK: u32 = 0x4102;
    /// bpf_list_pop_front
    pub const LIST_POP_FRONT: u32 = 0x4103;
    /// bpf_list_pop_back
    pub const LIST_POP_BACK: u32 = 0x4104;
}

/// Check if kfunc is a list operation
pub fn is_list_kfunc(kfunc_id: u32) -> bool {
    matches!(
        kfunc_id,
        list_kfuncs::LIST_PUSH_FRONT
            | list_kfuncs::LIST_PUSH_BACK
            | list_kfuncs::LIST_POP_FRONT
            | list_kfuncs::LIST_POP_BACK
    )
}

/// Check if kfunc is any graph data structure operation
pub fn is_graph_kfunc(kfunc_id: u32) -> bool {
    is_rbtree_kfunc(kfunc_id) || is_list_kfunc(kfunc_id)
}

// ============================================================================
// Container Pointer Offset Calculation (container_of)
// ============================================================================

/// Calculate pointer to containing structure from node pointer
/// 
/// Equivalent to Linux kernel's container_of() macro:
/// `container_of(ptr, type, member)` -> `(type *)((char *)(ptr) - offsetof(type, member))`
pub fn container_of_offset(node_ptr_off: i32, node_offset_in_container: i32) -> i32 {
    node_ptr_off - node_offset_in_container
}

/// Information about a container_of transformation
#[derive(Debug, Clone)]
pub struct ContainerOfInfo {
    /// BTF ID of the containing structure
    pub container_btf_id: u32,
    /// Offset of the node field within the container
    pub node_offset: i32,
    /// BTF ID of the node type
    pub node_btf_id: u32,
}

/// Validate container_of operation
/// 
/// When we have a pointer to bpf_rb_node inside a struct, we can convert
/// it to a pointer to the containing struct using the node offset
pub fn validate_container_of(
    node_btf_id: u32,
    expected_node_btf_id: u32,
    node_offset: i32,
) -> Result<()> {
    if node_btf_id != expected_node_btf_id {
        return Err(VerifierError::TypeMismatch {
            expected: format!("btf_id {} (node type)", expected_node_btf_id),
            got: format!("btf_id {}", node_btf_id),
        });
    }
    
    if node_offset < 0 {
        return Err(VerifierError::InvalidOffset(node_offset as i64));
    }
    
    Ok(())
}

// ============================================================================
// List Node Operations
// ============================================================================

/// Validate list head argument
pub fn validate_list_head_arg(
    reg: &BpfRegState,
    expected_btf_id: Option<u32>,
) -> Result<()> {
    // Must be a pointer to bpf_list_head
    if reg.reg_type != BpfRegType::PtrToBtfId && reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to bpf_list_head".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    if let Some(expected) = expected_btf_id {
        if reg.btf_id() != expected {
            return Err(VerifierError::TypeMismatch {
                expected: format!("btf_id {}", expected),
                got: format!("btf_id {}", reg.btf_id()),
            });
        }
    }

    Ok(())
}

/// Validate list node argument
pub fn validate_list_node_arg(
    reg: &BpfRegState,
    must_be_owned: bool,
) -> Result<()> {
    // Must be a pointer to struct containing bpf_list_node
    if reg.reg_type != BpfRegType::PtrToBtfId {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to bpf_list_node".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    // Check ownership if required
    if must_be_owned && reg.ref_obj_id == 0 {
        return Err(VerifierError::InvalidState(
            "list push requires owned node".into()
        ));
    }

    Ok(())
}

/// Process list_push return
pub fn process_list_push_return(
    ret_reg: &mut BpfRegState,
    _node_reg: &BpfRegState,
) {
    // bpf_list_push_* returns void, node is now in list
    ret_reg.mark_not_init(false);
}

/// Process list_pop return
pub fn process_list_pop_return(
    ret_reg: &mut BpfRegState,
    graph_root: &GraphRoot,
    ref_obj_id: u32,
) {
    // bpf_list_pop_* returns owned node pointer (or NULL)
    mark_reg_graph_node(ret_reg, graph_root);
    ret_reg.ref_obj_id = ref_obj_id;
    // PTR_MAYBE_NULL flag would be set
}

// ============================================================================
// Graph Field Record (for BTF-based graph field tracking)
// ============================================================================

/// Types of special BPF fields in structs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfFieldType {
    /// bpf_rb_root - root of an rbtree
    RbRoot,
    /// bpf_rb_node - node in an rbtree
    RbNode,
    /// bpf_list_head - head of a linked list
    ListHead,
    /// bpf_list_node - node in a linked list
    ListNode,
    /// bpf_refcount - reference count
    Refcount,
    /// bpf_spin_lock
    SpinLock,
}

/// A BPF field record for graph structures
#[derive(Debug, Clone)]
pub struct BpfFieldRecord {
    /// Type of the field
    pub field_type: BpfFieldType,
    /// Offset within the containing struct (bytes)
    pub offset: u32,
    /// Size of the field (bytes)
    pub size: u32,
    /// BTF ID of the containing struct
    pub container_btf_id: u32,
    /// For graph nodes: BTF ID of the associated graph root's value type
    pub graph_value_btf_id: Option<u32>,
    /// For graph nodes: offset of the root's node field
    pub graph_node_offset: Option<i32>,
}

impl BpfFieldRecord {
    /// Check if this is a graph root field
    pub fn is_graph_root(&self) -> bool {
        matches!(self.field_type, BpfFieldType::RbRoot | BpfFieldType::ListHead)
    }

    /// Check if this is a graph node field
    pub fn is_graph_node(&self) -> bool {
        matches!(self.field_type, BpfFieldType::RbNode | BpfFieldType::ListNode)
    }

    /// Get the graph type if this is a graph field
    pub fn graph_type(&self) -> Option<GraphType> {
        match self.field_type {
            BpfFieldType::RbRoot | BpfFieldType::RbNode => Some(GraphType::Rbtree),
            BpfFieldType::ListHead | BpfFieldType::ListNode => Some(GraphType::List),
            _ => None,
        }
    }
}

/// Storage for BPF field records parsed from BTF
#[derive(Debug, Clone, Default)]
pub struct BpfFieldRecords {
    /// Records by (btf_id, offset)
    records: HashMap<(u32, u32), BpfFieldRecord>,
    /// All records for a given BTF ID
    by_btf_id: HashMap<u32, Vec<u32>>, // btf_id -> list of offsets
}

impl BpfFieldRecords {
    /// Create a new records store
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a field record
    pub fn add_record(&mut self, record: BpfFieldRecord) {
        let btf_id = record.container_btf_id;
        let offset = record.offset;
        
        self.by_btf_id
            .entry(btf_id)
            .or_default()
            .push(offset);
        self.records.insert((btf_id, offset), record);
    }

    /// Get a field record by BTF ID and offset
    pub fn get_record(&self, btf_id: u32, offset: u32) -> Option<&BpfFieldRecord> {
        self.records.get(&(btf_id, offset))
    }

    /// Get all field records for a BTF ID
    pub fn get_records_for_type(&self, btf_id: u32) -> Vec<&BpfFieldRecord> {
        self.by_btf_id
            .get(&btf_id)
            .map(|offsets| {
                offsets.iter()
                    .filter_map(|off| self.records.get(&(btf_id, *off)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find graph root record for a graph node
    pub fn find_matching_root(&self, node_record: &BpfFieldRecord) -> Option<&BpfFieldRecord> {
        let target_graph_type = match node_record.field_type {
            BpfFieldType::RbNode => BpfFieldType::RbRoot,
            BpfFieldType::ListNode => BpfFieldType::ListHead,
            _ => return None,
        };

        // Search for a matching root with the same value BTF ID
        for record in self.records.values() {
            if record.field_type == target_graph_type {
                if let (Some(node_val), Some(root_val)) = 
                    (node_record.graph_value_btf_id, record.graph_value_btf_id)
                {
                    if node_val == root_val {
                        return Some(record);
                    }
                }
            }
        }

        None
    }
}

// ============================================================================
// Graph Safety Verification
// ============================================================================

/// Verify graph operation safety
pub fn verify_graph_op_safety(
    tracker: &GraphNodeTracker,
    node_ref_id: u32,
    op_type: GraphOpType,
) -> Result<()> {
    match op_type {
        GraphOpType::Insert => {
            // Node must be owned to insert
            if let Some(node) = tracker.get_node(node_ref_id) {
                if node.ownership != NodeOwnership::Owned {
                    return Err(VerifierError::InvalidState(
                        "can only insert owned nodes into graph".into()
                    ));
                }
            } else {
                return Err(VerifierError::InvalidState(
                    "node not found for insertion".into()
                ));
            }
        }
        GraphOpType::Remove => {
            // Node must be in graph to remove
            if let Some(node) = tracker.get_node(node_ref_id) {
                if node.ownership != NodeOwnership::InGraph {
                    return Err(VerifierError::InvalidState(
                        "can only remove nodes that are in graph".into()
                    ));
                }
            } else {
                return Err(VerifierError::InvalidState(
                    "node not found for removal".into()
                ));
            }
        }
        GraphOpType::Traverse => {
            // Traversal is always safe (returns non-owning reference)
            Ok(())?;
        }
    }
    
    Ok(())
}

/// Type of graph operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphOpType {
    /// Insert node into graph
    Insert,
    /// Remove node from graph
    Remove,
    /// Traverse graph (first, next, etc.)
    Traverse,
}

/// Map kfunc ID to graph operation type
pub fn kfunc_to_graph_op(kfunc_id: u32) -> Option<GraphOpType> {
    match kfunc_id {
        rbtree_kfuncs::RBTREE_ADD_IMPL => Some(GraphOpType::Insert),
        rbtree_kfuncs::RBTREE_REMOVE => Some(GraphOpType::Remove),
        rbtree_kfuncs::RBTREE_FIRST
        | rbtree_kfuncs::RBTREE_ROOT
        | rbtree_kfuncs::RBTREE_LEFT
        | rbtree_kfuncs::RBTREE_RIGHT => Some(GraphOpType::Traverse),
        list_kfuncs::LIST_PUSH_FRONT | list_kfuncs::LIST_PUSH_BACK => Some(GraphOpType::Insert),
        list_kfuncs::LIST_POP_FRONT | list_kfuncs::LIST_POP_BACK => Some(GraphOpType::Remove),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
