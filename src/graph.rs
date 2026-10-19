//! Stack-independent DAG validation shared by v2 and v3 packets.
use crate::SlbitError;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(crate) fn reject_cycles(
    ids: &BTreeSet<String>,
    adjacency: &BTreeMap<String, Vec<String>>,
) -> Result<(), SlbitError> {
    let mut incoming: BTreeMap<&str, usize> = ids.iter().map(|id| (id.as_str(), 0)).collect();
    for children in adjacency.values() {
        for child in children {
            // Callers already validated every edge endpoint.
            *incoming
                .get_mut(child.as_str())
                .expect("validated endpoint") += 1;
        }
    }
    let mut ready: VecDeque<&str> = incoming
        .iter()
        .filter_map(|(&id, &count)| (count == 0).then_some(id))
        .collect();
    let mut visited = 0;
    while let Some(node) = ready.pop_front() {
        visited += 1;
        if let Some(children) = adjacency.get(node) {
            for child in children {
                let count = incoming
                    .get_mut(child.as_str())
                    .expect("validated endpoint");
                *count -= 1;
                if *count == 0 {
                    ready.push_back(child);
                }
            }
        }
    }
    if visited == ids.len() {
        Ok(())
    } else {
        Err(SlbitError::CycleDetected)
    }
}
