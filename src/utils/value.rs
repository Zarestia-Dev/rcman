//! Common utilities for manipulating `serde_json::Value` trees.
//!
//! These functions allow deep merging and dot-separated path traversal
//! without re-implementing recursive logic across the codebase.

use serde_json::Value;

/// Deeply merges a source JSON value into a target JSON value.
///
/// If both the target and the source are objects, it merges their keys recursively.
/// Otherwise, the target is completely replaced by the source.
pub fn deep_merge(target: &mut Value, source: &Value) {
    match (target, source) {
        (Value::Object(target_map), Value::Object(source_map)) => {
            for (key, source_val) in source_map {
                if let Some(target_val) = target_map.get_mut(key) {
                    deep_merge(target_val, source_val);
                } else {
                    target_map.insert(key.clone(), source_val.clone());
                }
            }
        }
        (target, source) => {
            *target = source.clone();
        }
    }
}

/// Retrieve a value from a JSON tree using a dot-separated path (e.g., "parent.child.key").
///
/// Returns `None` if the path doesn't exist.
pub fn get_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// Check if a dot-separated path exists in the JSON tree.
pub fn path_exists(value: &Value, path: &str) -> bool {
    get_path(value, path).is_some()
}

/// Set a value in a JSON tree using a dot-separated path.
///
/// If any intermediate objects do not exist, they will be created as empty objects.
pub fn set_path(value: &mut Value, path: &str, new_value: Value) {
    if path.is_empty() {
        *value = new_value;
        return;
    }

    if !value.is_object() {
        *value = Value::Object(serde_json::Map::new());
    }

    let mut current = value;
    let mut parts = path.split('.').peekable();

    while let Some(segment) = parts.next() {
        if parts.peek().is_none() {
            if let Some(obj) = current.as_object_mut() {
                obj.insert(segment.to_string(), new_value);
            }
            return;
        }

        if let Some(obj) = current.as_object_mut() {
            let entry = obj
                .entry(segment.to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));

            if !entry.is_object() {
                *entry = Value::Object(serde_json::Map::new());
            }

            current = entry;
        } else {
            return;
        }
    }
}

/// Remove a value in a JSON tree using a dot-separated path.
///
/// Returns the removed value if it existed, otherwise `None`.
/// Cleans up empty intermediate objects ascending the tree.
pub fn remove_path(value: &mut Value, path: &str) -> Option<Value> {
    if path.is_empty() {
        let old = value.clone();
        *value = Value::Null; // replacing root
        return Some(old);
    }

    let parts: Vec<&str> = path.split('.').collect();
    let obj = value.as_object_mut()?;
    remove_nested(obj, &parts)
}

fn remove_nested(obj: &mut serde_json::Map<String, Value>, parts: &[&str]) -> Option<Value> {
    match parts {
        [] => None,
        [last] => obj.remove(*last),
        [head, rest @ ..] => {
            let child = obj.get_mut(*head)?;
            let child_obj = child.as_object_mut()?;
            let removed = remove_nested(child_obj, rest);
            // Clean up empty intermediate branch
            if child_obj.is_empty() {
                obj.remove(*head);
            }
            removed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_deep_merge() {
        let mut target = json!({
            "general": { "port": 8080, "host": "localhost" },
            "db": { "url": "sqlite://old.db" }
        });

        let source = json!({
            "general": { "port": 9090, "debug": true },
            "api": { "enabled": false }
        });

        deep_merge(&mut target, &source);

        let expected = json!({
            "general": { "port": 9090, "host": "localhost", "debug": true },
            "db": { "url": "sqlite://old.db" },
            "api": { "enabled": false }
        });

        assert_eq!(target, expected);
    }

    #[test]
    fn test_get_path() {
        let tree = json!({
            "a": { "b": { "c": 42 } },
            "flat": "value"
        });

        assert_eq!(get_path(&tree, "a.b.c"), Some(&json!(42)));
        assert_eq!(get_path(&tree, "flat"), Some(&json!("value")));
        assert_eq!(get_path(&tree, "a.missing"), None);
        assert_eq!(get_path(&tree, "missing.entirely"), None);

        // Empty path returns the root value
        assert_eq!(get_path(&tree, ""), Some(&tree));
    }

    #[test]
    fn test_set_path() {
        let mut tree = json!({ "existing": 1 });

        set_path(&mut tree, "new.nested.node", json!("hello"));
        assert_eq!(get_path(&tree, "new.nested.node"), Some(&json!("hello")));
        assert_eq!(get_path(&tree, "existing"), Some(&json!(1)));

        // Overwrites
        set_path(&mut tree, "existing", json!(2));
        assert_eq!(get_path(&tree, "existing"), Some(&json!(2)));

        // Turns scalar into object to set path
        set_path(&mut tree, "existing.deep", json!(3));
        assert_eq!(get_path(&tree, "existing.deep"), Some(&json!(3)));
    }

    #[test]
    fn test_remove_path() {
        let mut tree = json!({
            "a": { "b": { "c": 42, "d": 1 } },
            "keep": true
        });

        let removed = remove_path(&mut tree, "a.b.c");
        assert_eq!(removed, Some(json!(42)));
        assert_eq!(get_path(&tree, "a.b.c"), None);
        assert_eq!(get_path(&tree, "a.b.d"), Some(&json!(1)));

        // Removes intermediate empty nodes
        let removed_d = remove_path(&mut tree, "a.b.d");
        assert_eq!(removed_d, Some(json!(1)));
        assert_eq!(get_path(&tree, "a.b"), None); // "b" was removed because it was empty
        assert_eq!(get_path(&tree, "a"), None); // "a" was removed because it was empty

        assert_eq!(get_path(&tree, "keep"), Some(&json!(true)));
    }
}
