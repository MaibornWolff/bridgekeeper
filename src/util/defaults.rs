/// Returns the original api_group if it was not empty, otherwise returns "core"
pub fn api_group_or_default(api_group: &str) -> &str {
    if api_group.is_empty() { 
        "core" 
    } else { 
        api_group 
    }
}