//! Schema-driven semantic validation for sing-box configuration documents.
//!
//! JSON Schema validates the shape of a document. sing-box additionally
//! annotates reference fields with `x-tag-reference`, which lets Turntable
//! validate references without deserializing the complete configuration into
//! release-specific Rust models.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::Value;

use crate::config::schema;

/// A non-fatal issue discovered from schema annotations.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemanticWarning {
    /// A schema branch marked the value as deprecated.
    Deprecated {
        /// JSON Pointer locating the deprecated value.
        instance_path: String,
        /// JSON Pointer locating the deprecation annotation.
        schema_path: String,
    },
    /// Two fields are accepted but have conflicting runtime semantics.
    ConflictingFields {
        /// JSON Pointer locating the first field.
        first_path: String,
        /// JSON Pointer locating the second field.
        second_path: String,
        /// Human-readable explanation of the conflict.
        message: String,
    },
}

impl fmt::Display for SemanticWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deprecated {
                instance_path,
                schema_path,
            } => {
                let path = display_path(instance_path);
                write!(
                    f,
                    "{path}: value is deprecated by schema annotation {schema_path}"
                )
            }
            Self::ConflictingFields {
                first_path,
                second_path,
                message,
            } => write!(
                f,
                "{} conflicts with {}: {message}",
                display_path(first_path),
                display_path(second_path)
            ),
        }
    }
}

/// A semantic configuration violation not expressible by standard JSON Schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticViolation {
    /// A tag is defined more than once in a namespace.
    DuplicateTag {
        /// sing-box tag namespace.
        namespace: String,
        /// Duplicated tag.
        tag: String,
        /// JSON Pointer locating the first definition.
        first_path: String,
        /// JSON Pointer locating the duplicate definition.
        duplicate_path: String,
    },
    /// A definition which requires an explicit tag has none.
    MissingTag {
        /// sing-box tag namespace.
        namespace: String,
        /// JSON Pointer locating the untagged definition.
        instance_path: String,
    },
    /// The schema introduced a tag namespace Turntable cannot index yet.
    UnknownReferenceNamespace {
        /// Unknown namespace from `x-tag-reference`.
        namespace: String,
        /// JSON Pointer locating the reference.
        instance_path: String,
    },
    /// A tag reference does not resolve in its namespace.
    UnresolvedReference {
        /// sing-box tag namespace.
        namespace: String,
        /// Referenced tag.
        tag: String,
        /// JSON Pointer locating the reference.
        instance_path: String,
    },
    /// References between definitions form a dependency cycle.
    CircularReference {
        /// sing-box tag namespace.
        namespace: String,
        /// Cycle with the first tag repeated at the end.
        cycle: Vec<String>,
        /// JSON Pointer locating the edge which closed the cycle.
        instance_path: String,
    },
    /// A selector or URLTest contains no candidate outbounds.
    EmptyOutboundGroup {
        /// Group type (`selector` or `urltest`).
        group_type: String,
        /// JSON Pointer locating the group.
        instance_path: String,
    },
    /// A selector default is not one of its candidate outbounds.
    SelectorDefaultNotMember {
        /// Default outbound tag.
        tag: String,
        /// JSON Pointer locating the default field.
        instance_path: String,
    },
}

impl SemanticViolation {
    fn sort_key(&self) -> (&str, u8, &str) {
        match self {
            Self::DuplicateTag { duplicate_path, .. } => (duplicate_path, 0, ""),
            Self::MissingTag { instance_path, .. } => (instance_path, 1, ""),
            Self::UnknownReferenceNamespace { instance_path, .. } => (instance_path, 2, ""),
            Self::UnresolvedReference {
                instance_path, tag, ..
            } => (instance_path, 3, tag),
            Self::CircularReference {
                instance_path,
                namespace,
                ..
            } => (instance_path, 4, namespace),
            Self::EmptyOutboundGroup {
                instance_path,
                group_type,
            } => (instance_path, 5, group_type),
            Self::SelectorDefaultNotMember { instance_path, tag } => (instance_path, 6, tag),
        }
    }
}

impl fmt::Display for SemanticViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateTag {
                namespace,
                tag,
                first_path,
                duplicate_path,
            } => write!(
                f,
                "{}: duplicate {namespace} tag '{tag}' (first defined at {})",
                display_path(duplicate_path),
                display_path(first_path)
            ),
            Self::MissingTag {
                namespace,
                instance_path,
            } => write!(
                f,
                "{}: {namespace} definition requires a non-empty tag",
                display_path(instance_path)
            ),
            Self::UnknownReferenceNamespace {
                namespace,
                instance_path,
            } => write!(
                f,
                "{}: schema uses unsupported tag-reference namespace '{namespace}'",
                display_path(instance_path)
            ),
            Self::UnresolvedReference {
                namespace,
                tag,
                instance_path,
            } => write!(
                f,
                "{}: {namespace} tag reference '{tag}' does not exist",
                display_path(instance_path)
            ),
            Self::CircularReference {
                namespace,
                cycle,
                instance_path,
            } => write!(
                f,
                "{}: circular {namespace} dependency: {}",
                display_path(instance_path),
                cycle.join(" -> ")
            ),
            Self::EmptyOutboundGroup {
                group_type,
                instance_path,
            } => write!(
                f,
                "{}: {group_type} must contain at least one outbound",
                display_path(instance_path)
            ),
            Self::SelectorDefaultNotMember { tag, instance_path } => write!(
                f,
                "{}: selector default '{tag}' is not present in its outbounds",
                display_path(instance_path)
            ),
        }
    }
}

/// All semantic violations found in a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticValidationError {
    violations: Vec<SemanticViolation>,
}

impl SemanticValidationError {
    /// Return every semantic violation in deterministic instance-path order.
    pub fn violations(&self) -> &[SemanticViolation] {
        &self.violations
    }
}

impl fmt::Display for SemanticValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "sing-box semantic validation failed with {} error(s)",
            self.violations.len()
        )?;
        for violation in &self.violations {
            writeln!(f, "- {violation}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SemanticValidationError {}

#[derive(Clone, Copy)]
struct TagSource {
    namespace: &'static str,
    pointer: &'static str,
    implicit_index: bool,
}

// sing-box's outbound and endpoint managers intentionally share one namespace.
// All other sources correspond directly to x-tag-reference namespace names.
const TAG_SOURCES: &[TagSource] = &[
    TagSource {
        namespace: "outbound",
        pointer: "/outbounds",
        implicit_index: true,
    },
    TagSource {
        namespace: "outbound",
        pointer: "/endpoints",
        implicit_index: true,
    },
    TagSource {
        namespace: "inbound",
        pointer: "/inbounds",
        implicit_index: true,
    },
    TagSource {
        namespace: "dns_server",
        pointer: "/dns/servers",
        implicit_index: true,
    },
    TagSource {
        namespace: "rule_set",
        pointer: "/route/rule_set",
        implicit_index: false,
    },
    TagSource {
        namespace: "http_client",
        pointer: "/http_clients",
        implicit_index: false,
    },
    TagSource {
        namespace: "certificate_provider",
        pointer: "/certificate_providers",
        implicit_index: true,
    },
    TagSource {
        namespace: "network_namespace",
        pointer: "/network_namespaces",
        implicit_index: false,
    },
];

#[derive(Clone, Debug)]
struct TagDefinition {
    namespace: &'static str,
    tag: String,
    tag_path: String,
    root_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TagReference {
    namespace: String,
    tag: String,
    instance_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct GraphNode {
    namespace: String,
    tag: String,
}

type Symbols = BTreeMap<&'static str, BTreeMap<String, TagDefinition>>;
type DependencyGraph = BTreeMap<GraphNode, BTreeMap<GraphNode, String>>;

/// Validate cross-references and generator invariants in a schema-valid
/// sing-box document.
///
/// The caller must validate the document with [`schema::validate`] first.
/// Schema evaluation annotations are only meaningful for matching branches.
pub fn validate(document: &Value) -> Result<Vec<SemanticWarning>, SemanticValidationError> {
    validate_with_schema(document, schema::default_bundle())
}

/// Validate with the annotations from a specific bundled schema release.
pub fn validate_with_schema(
    document: &Value,
    schema_bundle: &'static schema::SchemaBundle,
) -> Result<Vec<SemanticWarning>, SemanticValidationError> {
    let mut violations = Vec::new();
    let (definitions, symbols) = collect_definitions(document, &mut violations);
    let annotations = schema_bundle.annotations(document);
    let references = collect_references(document, &annotations);

    check_references(&references, &symbols, &mut violations);
    check_outbound_groups(document, &mut violations);

    let graph = build_dependency_graph(&definitions, &symbols, &references);
    check_cycles(&graph, &mut violations);

    violations.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    let warnings = collect_warnings(document, &annotations);
    if violations.is_empty() {
        Ok(warnings)
    } else {
        Err(SemanticValidationError { violations })
    }
}

fn collect_definitions(
    document: &Value,
    violations: &mut Vec<SemanticViolation>,
) -> (Vec<TagDefinition>, Symbols) {
    let mut definitions = Vec::new();
    let mut symbols: Symbols = TAG_SOURCES
        .iter()
        .map(|source| (source.namespace, BTreeMap::new()))
        .collect();

    for source in TAG_SOURCES {
        let Some(items) = document.pointer(source.pointer).and_then(Value::as_array) else {
            continue;
        };

        for (index, item) in items.iter().enumerate() {
            let Some(object) = item.as_object() else {
                continue;
            };
            let root_path = format!("{}/{}", source.pointer, index);
            let tag_value = object.get("tag");
            let tags = definition_tags(tag_value, source, index, &root_path, violations);

            for (tag, tag_path) in tags {
                let definition = TagDefinition {
                    namespace: source.namespace,
                    tag: tag.clone(),
                    tag_path: tag_path.clone(),
                    root_path: root_path.clone(),
                };
                let namespace_symbols = symbols
                    .get_mut(source.namespace)
                    .expect("all tag sources initialize their namespace");

                if let Some(first) = namespace_symbols.get(&tag) {
                    violations.push(SemanticViolation::DuplicateTag {
                        namespace: source.namespace.to_string(),
                        tag,
                        first_path: first.tag_path.clone(),
                        duplicate_path: tag_path,
                    });
                } else {
                    namespace_symbols.insert(tag, definition.clone());
                }
                definitions.push(definition);
            }
        }
    }

    (definitions, symbols)
}

fn definition_tags(
    tag_value: Option<&Value>,
    source: &TagSource,
    index: usize,
    root_path: &str,
    violations: &mut Vec<SemanticViolation>,
) -> Vec<(String, String)> {
    match tag_value {
        Some(Value::String(tag)) if !tag.is_empty() => {
            vec![(tag.clone(), format!("{root_path}/tag"))]
        }
        Some(Value::Array(tags)) => tags
            .iter()
            .enumerate()
            .filter_map(|(tag_index, tag)| {
                let path = format!("{root_path}/tag/{tag_index}");
                match tag.as_str() {
                    Some("") | None => {
                        violations.push(SemanticViolation::MissingTag {
                            namespace: source.namespace.to_string(),
                            instance_path: path,
                        });
                        None
                    }
                    Some(tag) => Some((tag.to_string(), path)),
                }
            })
            .collect(),
        None | Some(Value::String(_)) if source.implicit_index => {
            vec![(index.to_string(), root_path.to_string())]
        }
        None | Some(Value::String(_)) => {
            violations.push(SemanticViolation::MissingTag {
                namespace: source.namespace.to_string(),
                instance_path: format!("{root_path}/tag"),
            });
            Vec::new()
        }
        Some(_) => Vec::new(),
    }
}

fn collect_references(
    document: &Value,
    annotations: &[schema::SchemaAnnotation],
) -> Vec<TagReference> {
    let mut references = BTreeSet::new();

    for annotation in annotations {
        let Some(namespace) = annotation
            .value
            .as_object()
            .and_then(|value| value.get("x-tag-reference"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(value) = document.pointer(&annotation.instance_path) else {
            continue;
        };

        collect_reference_values(value, namespace, &annotation.instance_path, &mut references);
    }

    references.into_iter().collect()
}

fn collect_reference_values(
    value: &Value,
    namespace: &str,
    instance_path: &str,
    references: &mut BTreeSet<TagReference>,
) {
    match value {
        Value::String(tag) if !tag.is_empty() => {
            references.insert(TagReference {
                namespace: namespace.to_string(),
                tag: tag.clone(),
                instance_path: instance_path.to_string(),
            });
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_reference_values(
                    value,
                    namespace,
                    &format!("{instance_path}/{index}"),
                    references,
                );
            }
        }
        _ => {}
    }
}

fn check_references(
    references: &[TagReference],
    symbols: &Symbols,
    violations: &mut Vec<SemanticViolation>,
) {
    for reference in references {
        let Some(namespace) = symbols.get(reference.namespace.as_str()) else {
            violations.push(SemanticViolation::UnknownReferenceNamespace {
                namespace: reference.namespace.clone(),
                instance_path: reference.instance_path.clone(),
            });
            continue;
        };
        if !namespace.contains_key(&reference.tag) {
            violations.push(SemanticViolation::UnresolvedReference {
                namespace: reference.namespace.clone(),
                tag: reference.tag.clone(),
                instance_path: reference.instance_path.clone(),
            });
        }
    }
}

fn build_dependency_graph(
    definitions: &[TagDefinition],
    symbols: &Symbols,
    references: &[TagReference],
) -> DependencyGraph {
    let mut graph = DependencyGraph::new();

    for definition in definitions {
        graph
            .entry(GraphNode {
                namespace: definition.namespace.to_string(),
                tag: definition.tag.clone(),
            })
            .or_default();
    }

    for reference in references {
        let Some(namespace) = symbols.get(reference.namespace.as_str()) else {
            continue;
        };
        if !namespace.contains_key(&reference.tag) {
            continue;
        }

        for owner in definitions.iter().filter(|definition| {
            definition.namespace == reference.namespace
                && pointer_is_within(&reference.instance_path, &definition.root_path)
        }) {
            let source = GraphNode {
                namespace: owner.namespace.to_string(),
                tag: owner.tag.clone(),
            };
            let target = GraphNode {
                namespace: reference.namespace.clone(),
                tag: reference.tag.clone(),
            };
            graph
                .entry(source)
                .or_default()
                .entry(target)
                .or_insert_with(|| reference.instance_path.clone());
        }
    }

    graph
}

fn check_cycles(graph: &DependencyGraph, violations: &mut Vec<SemanticViolation>) {
    let mut states: BTreeMap<GraphNode, VisitState> = BTreeMap::new();
    let mut stack = Vec::new();
    let mut reported = BTreeSet::new();

    for node in graph.keys() {
        if !states.contains_key(node) {
            visit_dependencies(
                node,
                graph,
                &mut states,
                &mut stack,
                &mut reported,
                violations,
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Complete,
}

fn visit_dependencies(
    node: &GraphNode,
    graph: &DependencyGraph,
    states: &mut BTreeMap<GraphNode, VisitState>,
    stack: &mut Vec<GraphNode>,
    reported: &mut BTreeSet<Vec<GraphNode>>,
    violations: &mut Vec<SemanticViolation>,
) {
    states.insert(node.clone(), VisitState::Visiting);
    stack.push(node.clone());

    if let Some(edges) = graph.get(node) {
        for (target, instance_path) in edges {
            match states.get(target) {
                Some(VisitState::Visiting) => {
                    let start = stack
                        .iter()
                        .position(|candidate| candidate == target)
                        .expect("a visiting dependency must be on the DFS stack");
                    let mut cycle = stack[start..].to_vec();
                    cycle.push(target.clone());
                    let canonical = canonical_cycle(&cycle);
                    if reported.insert(canonical.clone()) {
                        violations.push(SemanticViolation::CircularReference {
                            namespace: target.namespace.clone(),
                            cycle: canonical.iter().map(|item| item.tag.clone()).collect(),
                            instance_path: instance_path.clone(),
                        });
                    }
                }
                Some(VisitState::Complete) => {}
                None => visit_dependencies(target, graph, states, stack, reported, violations),
            }
        }
    }

    stack.pop();
    states.insert(node.clone(), VisitState::Complete);
}

fn canonical_cycle(cycle: &[GraphNode]) -> Vec<GraphNode> {
    let ring = &cycle[..cycle.len() - 1];
    let mut best = ring.to_vec();

    for offset in 1..ring.len() {
        let candidate = ring[offset..]
            .iter()
            .chain(&ring[..offset])
            .cloned()
            .collect::<Vec<_>>();
        if candidate < best {
            best = candidate;
        }
    }

    best.push(best[0].clone());
    best
}

fn check_outbound_groups(document: &Value, violations: &mut Vec<SemanticViolation>) {
    let Some(outbounds) = document.pointer("/outbounds").and_then(Value::as_array) else {
        return;
    };

    for (index, outbound) in outbounds.iter().enumerate() {
        let Some(object) = outbound.as_object() else {
            continue;
        };
        let Some(group_type @ ("selector" | "urltest")) =
            object.get("type").and_then(Value::as_str)
        else {
            continue;
        };
        let group_path = format!("/outbounds/{index}");
        let targets = object
            .get("outbounds")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();

        if targets.is_empty() {
            violations.push(SemanticViolation::EmptyOutboundGroup {
                group_type: group_type.to_string(),
                instance_path: format!("{group_path}/outbounds"),
            });
        }

        if group_type == "selector"
            && let Some(default) = object.get("default").and_then(Value::as_str)
            && !default.is_empty()
            && !targets
                .iter()
                .any(|target| target.as_str() == Some(default))
        {
            violations.push(SemanticViolation::SelectorDefaultNotMember {
                tag: default.to_string(),
                instance_path: format!("{group_path}/default"),
            });
        }
    }
}

fn collect_warnings(
    document: &Value,
    annotations: &[schema::SchemaAnnotation],
) -> Vec<SemanticWarning> {
    let mut warnings = BTreeSet::new();

    for annotation in annotations {
        let direct_deprecation = annotation.schema_path.ends_with("/deprecated")
            && annotation.value.as_bool() == Some(true);
        let bundled_deprecation = annotation
            .value
            .as_object()
            .and_then(|value| value.get("deprecated"))
            .and_then(Value::as_bool)
            == Some(true);

        if direct_deprecation || bundled_deprecation {
            warnings.insert(SemanticWarning::Deprecated {
                instance_path: annotation.instance_path.clone(),
                schema_path: annotation.schema_path.clone(),
            });
        }
    }

    collect_conflict_warnings(document, "", &mut warnings);

    warnings.into_iter().collect()
}

fn collect_conflict_warnings(value: &Value, path: &str, warnings: &mut BTreeSet<SemanticWarning>) {
    match value {
        Value::Object(object) => {
            if object.contains_key("network_strategy") {
                for bind_field in ["bind_interface", "inet4_bind_address", "inet6_bind_address"] {
                    if object.contains_key(bind_field) {
                        warnings.insert(SemanticWarning::ConflictingFields {
                            first_path: child_pointer(path, "network_strategy"),
                            second_path: child_pointer(path, bind_field),
                            message: format!(
                                "'{bind_field}' is ignored when 'network_strategy' is configured"
                            ),
                        });
                    }
                }
            }

            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("hysteria" | "hysteria2")
            ) && object.contains_key("server_port")
                && object
                    .get("server_ports")
                    .and_then(Value::as_array)
                    .is_some_and(|ports| !ports.is_empty())
            {
                warnings.insert(SemanticWarning::ConflictingFields {
                    first_path: child_pointer(path, "server_port"),
                    second_path: child_pointer(path, "server_ports"),
                    message: "'server_port' is ignored when 'server_ports' is configured"
                        .to_string(),
                });
            }

            for (key, child) in object {
                collect_conflict_warnings(child, &child_pointer(path, key), warnings);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_conflict_warnings(child, &format!("{path}/{index}"), warnings);
            }
        }
        _ => {}
    }

    if path.is_empty()
        && let Some(route) = value.get("route").and_then(Value::as_object)
        && route.contains_key("default_interface")
        && route.contains_key("default_network_strategy")
    {
        warnings.insert(SemanticWarning::ConflictingFields {
            first_path: "/route/default_interface".to_string(),
            second_path: "/route/default_network_strategy".to_string(),
            message: "'default_interface' is ignored when 'default_network_strategy' is configured"
                .to_string(),
        });
    }
}

fn child_pointer(parent: &str, child: &str) -> String {
    let escaped = child.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{escaped}")
}

fn pointer_is_within(pointer: &str, root: &str) -> bool {
    pointer == root
        || pointer
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn display_path(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn validate_document(
        document: &Value,
    ) -> Result<Vec<SemanticWarning>, SemanticValidationError> {
        schema::validate(document).expect("semantic tests must use schema-valid documents");
        validate(document)
    }

    #[test]
    fn accepts_resolved_schema_annotated_references() {
        let document = json!({
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": ["direct"],
                    "default": "direct"
                }
            ],
            "route": {"final": "proxy"}
        });

        assert_eq!(validate_document(&document).unwrap(), Vec::new());
    }

    #[test]
    fn reports_references_from_schema_annotations() {
        let document = json!({
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "experimental": {
                "clash_api": {
                    "external_ui_download_detour": "missing"
                }
            }
        });

        let error = validate_document(&document).unwrap_err();
        assert!(error.violations().iter().any(|violation| {
            matches!(
                violation,
                SemanticViolation::UnresolvedReference {
                    namespace,
                    tag,
                    instance_path
                } if namespace == "outbound"
                    && tag == "missing"
                    && instance_path == "/experimental/clash_api/external_ui_download_detour"
            )
        }));
    }

    #[test]
    fn reports_duplicate_tags_across_outbounds_and_endpoints() {
        let document = json!({
            "endpoints": [{
                "type": "wireguard",
                "tag": "duplicate",
                "address": ["10.0.0.1/32"],
                "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            }],
            "outbounds": [{"type": "direct", "tag": "duplicate"}]
        });

        let error = validate_document(&document).unwrap_err();
        assert!(error.violations().iter().any(|violation| {
            matches!(
                violation,
                SemanticViolation::DuplicateTag { namespace, tag, .. }
                    if namespace == "outbound" && tag == "duplicate"
            )
        }));
    }

    #[test]
    fn detects_outbound_dependency_cycles() {
        let document = json!({
            "outbounds": [
                {
                    "type": "selector",
                    "tag": "a",
                    "outbounds": ["b"]
                },
                {
                    "type": "selector",
                    "tag": "b",
                    "outbounds": ["a"]
                }
            ]
        });

        let error = validate_document(&document).unwrap_err();
        assert!(error.violations().iter().any(|violation| {
            matches!(
                violation,
                SemanticViolation::CircularReference {
                    namespace,
                    cycle,
                    ..
                } if namespace == "outbound" && cycle == &vec!["a", "b", "a"]
            )
        }));
    }

    #[test]
    fn checks_outbound_group_invariants() {
        let document = json!({
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "selector",
                    "tag": "empty",
                    "outbounds": []
                },
                {
                    "type": "selector",
                    "tag": "bad-default",
                    "outbounds": ["direct"],
                    "default": "bad-default"
                }
            ]
        });

        let error = validate_document(&document).unwrap_err();
        assert!(error.violations().iter().any(|violation| matches!(
            violation,
            SemanticViolation::EmptyOutboundGroup { instance_path, .. }
                if instance_path == "/outbounds/1/outbounds"
        )));
        assert!(error.violations().iter().any(|violation| matches!(
            violation,
            SemanticViolation::SelectorDefaultNotMember { instance_path, .. }
                if instance_path == "/outbounds/2/default"
        )));
    }

    #[test]
    fn implicit_index_tags_match_sing_box_behavior() {
        let document = json!({
            "outbounds": [
                {"type": "direct"},
                {
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": ["0"]
                }
            ]
        });

        assert_eq!(validate_document(&document).unwrap(), Vec::new());
    }

    #[test]
    fn bundled_schema_reference_namespaces_are_all_indexed() {
        fn collect_namespaces(value: &Value, namespaces: &mut BTreeSet<String>) {
            match value {
                Value::Object(object) => {
                    if let Some(namespace) = object.get("x-tag-reference").and_then(Value::as_str) {
                        namespaces.insert(namespace.to_string());
                    }
                    for child in object.values() {
                        collect_namespaces(child, namespaces);
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        collect_namespaces(child, namespaces);
                    }
                }
                _ => {}
            }
        }

        let mut schema_namespaces = BTreeSet::new();
        collect_namespaces(schema::official_schema(), &mut schema_namespaces);
        let indexed_namespaces = TAG_SOURCES
            .iter()
            .map(|source| source.namespace.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(schema_namespaces, indexed_namespaces);
    }

    #[test]
    fn reports_raw_document_conflict_warnings() {
        let document = json!({
            "outbounds": [{
                "type": "hysteria2",
                "tag": "proxy",
                "server": "example.com",
                "server_port": 443,
                "server_ports": ["8443"],
                "password": "secret",
                "network_strategy": "hybrid",
                "bind_interface": "en0"
            }]
        });

        let warnings = validate_document(&document).unwrap();
        assert!(warnings.iter().any(|warning| matches!(
            warning,
            SemanticWarning::ConflictingFields {
                first_path,
                second_path,
                ..
            } if first_path == "/outbounds/0/server_port"
                && second_path == "/outbounds/0/server_ports"
        )));
        assert!(warnings.iter().any(|warning| matches!(
            warning,
            SemanticWarning::ConflictingFields {
                first_path,
                second_path,
                ..
            } if first_path == "/outbounds/0/network_strategy"
                && second_path == "/outbounds/0/bind_interface"
        )));
    }
}
