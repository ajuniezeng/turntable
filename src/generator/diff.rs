//! Subscription diff functionality
//!
//! This module provides functionality to compare subscription outbounds
//! and display the differences between cached and newly fetched versions.

use std::collections::HashSet;

use tracing::info;

use crate::config::outbound::Outbound;
use crate::transform::get_outbound_tag;

// ============================================================================
// Diff Functions
// ============================================================================

/// Result of diffing two sets of outbounds
#[derive(Debug, Clone)]
pub struct DiffResult {
    /// Tags that were added (present in new, not in old)
    pub added: Vec<String>,
    /// Tags that were removed (present in old, not in new)
    pub removed: Vec<String>,
    /// Total count in the new set
    pub new_count: usize,
}

impl DiffResult {
    /// Check if there are any changes
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty()
    }
}

/// Compare two sets of outbounds and return the differences
pub fn diff_outbounds(old: &[Outbound], new: &[Outbound]) -> DiffResult {
    let old_tags: HashSet<String> = old
        .iter()
        .filter_map(|o| get_outbound_tag(o).map(|s| s.to_string()))
        .collect();

    let new_tags: HashSet<String> = new
        .iter()
        .filter_map(|o| get_outbound_tag(o).map(|s| s.to_string()))
        .collect();

    let added: Vec<String> = new_tags.difference(&old_tags).cloned().collect();
    let removed: Vec<String> = old_tags.difference(&new_tags).cloned().collect();

    DiffResult {
        added,
        removed,
        new_count: new_tags.len(),
    }
}

/// Log the differences between old and new outbounds for a subscription
pub fn log_diff(subscription_name: &str, old: &[Outbound], new: &[Outbound]) {
    let result = diff_outbounds(old, new);

    if !result.has_changes() {
        info!(
            "Subscription '{}': No changes ({} outbounds)",
            subscription_name, result.new_count
        );
        return;
    }

    info!(
        "Subscription '{}' changes: +{} added, -{} removed",
        subscription_name,
        result.added.len(),
        result.removed.len()
    );

    if !result.added.is_empty() {
        info!("  Added ({}):", result.added.len());
        for tag in &result.added {
            info!("    + {}", tag);
        }
    }

    if !result.removed.is_empty() {
        info!("  Removed ({}):", result.removed.len());
        for tag in &result.removed {
            info!("    - {}", tag);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::outbound::DirectOutbound;

    fn make_direct_outbound(tag: &str) -> Outbound {
        Outbound::Direct(DirectOutbound::new(tag))
    }

    #[test]
    fn test_diff_outbounds_no_changes() {
        let old = vec![make_direct_outbound("node1"), make_direct_outbound("node2")];
        let new = vec![make_direct_outbound("node1"), make_direct_outbound("node2")];

        let result = diff_outbounds(&old, &new);
        assert!(!result.has_changes());
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert_eq!(result.new_count, 2);
    }

    #[test]
    fn test_diff_outbounds_with_additions() {
        let old = vec![make_direct_outbound("node1")];
        let new = vec![
            make_direct_outbound("node1"),
            make_direct_outbound("node2"),
            make_direct_outbound("node3"),
        ];

        let result = diff_outbounds(&old, &new);
        assert!(result.has_changes());
        assert_eq!(result.added.len(), 2);
        assert!(result.added.contains(&"node2".to_string()));
        assert!(result.added.contains(&"node3".to_string()));
        assert!(result.removed.is_empty());
        assert_eq!(result.new_count, 3);
    }

    #[test]
    fn test_diff_outbounds_with_removals() {
        let old = vec![
            make_direct_outbound("node1"),
            make_direct_outbound("node2"),
            make_direct_outbound("node3"),
        ];
        let new = vec![make_direct_outbound("node1")];

        let result = diff_outbounds(&old, &new);
        assert!(result.has_changes());
        assert!(result.added.is_empty());
        assert_eq!(result.removed.len(), 2);
        assert!(result.removed.contains(&"node2".to_string()));
        assert!(result.removed.contains(&"node3".to_string()));
        assert_eq!(result.new_count, 1);
    }

    #[test]
    fn test_diff_outbounds_with_both() {
        let old = vec![make_direct_outbound("node1"), make_direct_outbound("node2")];
        let new = vec![make_direct_outbound("node1"), make_direct_outbound("node3")];

        let result = diff_outbounds(&old, &new);
        assert!(result.has_changes());
        assert_eq!(result.added.len(), 1);
        assert!(result.added.contains(&"node3".to_string()));
        assert_eq!(result.removed.len(), 1);
        assert!(result.removed.contains(&"node2".to_string()));
        assert_eq!(result.new_count, 2);
    }

    #[test]
    fn test_diff_outbounds_empty_old() {
        let old: Vec<Outbound> = vec![];
        let new = vec![make_direct_outbound("node1"), make_direct_outbound("node2")];

        let result = diff_outbounds(&old, &new);
        assert!(result.has_changes());
        assert_eq!(result.added.len(), 2);
        assert!(result.removed.is_empty());
    }

    #[test]
    fn test_diff_outbounds_empty_new() {
        let old = vec![make_direct_outbound("node1"), make_direct_outbound("node2")];
        let new: Vec<Outbound> = vec![];

        let result = diff_outbounds(&old, &new);
        assert!(result.has_changes());
        assert!(result.added.is_empty());
        assert_eq!(result.removed.len(), 2);
        assert_eq!(result.new_count, 0);
    }

    #[test]
    fn test_diff_outbounds_both_empty() {
        let old: Vec<Outbound> = vec![];
        let new: Vec<Outbound> = vec![];

        let result = diff_outbounds(&old, &new);
        assert!(!result.has_changes());
        assert_eq!(result.new_count, 0);
    }

    #[test]
    fn test_diff_result_has_changes_only_added() {
        let result = DiffResult {
            added: vec!["node1".to_string()],
            removed: vec![],
            new_count: 1,
        };
        assert!(result.has_changes());
    }

    #[test]
    fn test_diff_result_has_changes_only_removed() {
        let result = DiffResult {
            added: vec![],
            removed: vec!["node1".to_string()],
            new_count: 0,
        };
        assert!(result.has_changes());
    }

    #[test]
    fn test_diff_result_no_changes() {
        let result = DiffResult {
            added: vec![],
            removed: vec![],
            new_count: 5,
        };
        assert!(!result.has_changes());
    }
}
