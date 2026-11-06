//! Reader for the offsets.hpp pack that offset dumps ship.
//!
//! The file is a flat list of `namespace X { inline constexpr uintptr_t Y = 0xZ; }`,
//! so a line-oriented state machine is enough — no C++ parser needed.

#[derive(Debug, Clone)]
pub struct Entry {
    pub namespace: String,
    pub name: String,
    pub value: u64,
}

#[derive(Debug, Default)]
pub struct Pack {
    pub client_version: Option<String>,
    pub entries: Vec<Entry>,
}

/// Entries whose value is an RVA into the module rather than a struct offset.
const POINTER_SLOTS: [(&str, &str); 3] = [
    ("TaskScheduler", "Pointer"),
    ("FakeDataModel", "Pointer"),
    ("VisualEngine", "Pointer"),
];

impl Pack {
    pub fn parse(text: &str) -> Pack {
        let mut pack = Pack::default();
        let mut scope: Vec<String> = Vec::new();

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(rest) = line.strip_prefix("inline std::string ClientVersion") {
                if let Some(value) = rest.split('"').nth(1) {
                    pack.client_version = Some(value.to_string());
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("namespace ") {
                if let Some(name) = rest.split_whitespace().next() {
                    scope.push(name.to_string());
                }
                continue;
            }

            if line.starts_with('}') {
                // A namespace body always closes with `}`; one level per line.
                for _ in 0..line.matches('}').count() {
                    scope.pop();
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("inline constexpr uintptr_t ") {
                if let Some((name, value)) = parse_assignment(rest) {
                    pack.entries.push(Entry {
                        namespace: scope.last().cloned().unwrap_or_default(),
                        name,
                        value,
                    });
                }
            }
        }

        pack
    }

    pub fn pointer_slots(&self) -> Vec<&Entry> {
        POINTER_SLOTS
            .iter()
            .filter_map(|(namespace, name)| {
                self.entries
                    .iter()
                    .find(|e| e.namespace == *namespace && e.name == *name)
            })
            .collect()
    }
}

fn parse_assignment(text: &str) -> Option<(String, u64)> {
    let (name, value) = text.split_once('=')?;
    let name = name.trim().to_string();
    let value = value.trim().trim_end_matches(';').trim();
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => value.parse::<u64>().ok()?,
    };
    Some((name, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
#pragma once
namespace Offsets {
    inline std::string ClientVersion = "version-abc123";

    namespace Instance {
         inline constexpr uintptr_t ChildrenStart = 0x70;
         inline constexpr uintptr_t Name = 0x0;
    }

    namespace TaskScheduler {
         inline constexpr uintptr_t Pointer = 0x8e4d7b8;
    }
}
"#;

    #[test]
    fn reads_version_and_entries() {
        let pack = Pack::parse(SAMPLE);
        assert_eq!(pack.client_version.as_deref(), Some("version-abc123"));
        assert_eq!(pack.entries.len(), 3);
        assert_eq!(pack.entries[0].namespace, "Instance");
        assert_eq!(pack.entries[0].name, "ChildrenStart");
        assert_eq!(pack.entries[0].value, 0x70);
    }

    #[test]
    fn finds_pointer_slots_only() {
        let pack = Pack::parse(SAMPLE);
        let slots = pack.pointer_slots();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].namespace, "TaskScheduler");
        assert_eq!(slots[0].value, 0x8e4d7b8);
    }

    #[test]
    fn scope_resets_after_closing_brace() {
        let pack = Pack::parse(SAMPLE);
        assert_eq!(pack.entries.last().unwrap().namespace, "TaskScheduler");
    }
}
