use serde::Deserialize;
use sigil_vault::SigilService;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct ImportItemDto {
    pub id: Option<String>,
    pub label: String,
    pub secret: String,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

/// Imports credentials from a JSON or CSV file into the designated vault collection.
pub async fn import_credentials_file(
    service: &SigilService,
    file_path: &Path,
    collection_id: &str,
    format: Option<&str>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;
    let is_json = match format {
        Some("json") => true,
        Some("csv") => false,
        _ => file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("json"))
            .unwrap_or(content.trim_start().starts_with('[')),
    };

    let items = if is_json {
        parse_json_items(&content)?
    } else {
        parse_csv_items(&content)?
    };

    // Ensure target collection exists, auto-creating if necessary
    if !service
        .get_collection_ids()
        .await
        .contains(&collection_id.to_string())
    {
        service
            .create_collection(collection_id, collection_id)
            .await?;
    }

    let count = items.len();
    for (idx, item) in items.into_iter().enumerate() {
        let item_id = item.id.unwrap_or_else(|| {
            let clean_label: String = item
                .label
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if clean_label.is_empty() {
                format!("imported_item_{idx}")
            } else {
                format!("{clean_label}_{idx}")
            }
        });

        service
            .set_item(
                collection_id,
                &item_id,
                &item.label,
                item.attributes,
                item.secret.as_bytes(),
                "text/plain",
                true,
            )
            .await?;
    }

    Ok(count)
}

fn parse_json_items(content: &str) -> Result<Vec<ImportItemDto>, Box<dyn std::error::Error>> {
    let items: Vec<ImportItemDto> = serde_json::from_str(content)?;
    Ok(items)
}

fn parse_csv_items(content: &str) -> Result<Vec<ImportItemDto>, Box<dyn std::error::Error>> {
    let mut items = Vec::new();
    let mut lines = content.lines();

    // Check if first line is header
    let first_line = match lines.next() {
        Some(l) => l.trim(),
        None => return Ok(items),
    };

    let is_header = first_line.to_lowercase().contains("label")
        || first_line.to_lowercase().contains("secret")
        || first_line.to_lowercase().contains("password");

    if !is_header {
        if let Some(item) = parse_csv_line(first_line) {
            items.push(item);
        }
    }

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(item) = parse_csv_line(trimmed) {
            items.push(item);
        }
    }

    Ok(items)
}

fn parse_csv_line(line: &str) -> Option<ImportItemDto> {
    // Simple robust comma splitting (handling optional quotes)
    let parts: Vec<&str> = line
        .split(',')
        .map(|s| s.trim().trim_matches('"'))
        .collect();
    if parts.len() < 2 {
        return None;
    }

    let label = parts[0].to_string();
    let secret = parts[1].to_string();
    let mut attributes = HashMap::new();

    if parts.len() >= 3 && !parts[2].is_empty() {
        attributes.insert("user".into(), parts[2].to_string());
    }
    if parts.len() >= 4 && !parts[3].is_empty() {
        attributes.insert("server".into(), parts[3].to_string());
    }

    Some(ImportItemDto {
        id: None,
        label,
        secret,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_items() {
        let json = r#"[
            {
                "id": "gh-token",
                "label": "GitHub Personal Token",
                "secret": "ghp_1234567890",
                "attributes": { "user": "alice", "server": "github.com" }
            }
        ]"#;
        let items = parse_json_items(json).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "GitHub Personal Token");
        assert_eq!(items[0].secret, "ghp_1234567890");
        assert_eq!(items[0].attributes.get("user").unwrap(), "alice");
    }

    #[test]
    fn test_parse_csv_items() {
        let csv = "label,secret,user,server\nGoogle Account,my-secret,alice@gmail.com,google.com\nAWS Token,aws-key-999,bob,aws.amazon.com";
        let items = parse_csv_items(csv).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "Google Account");
        assert_eq!(items[0].secret, "my-secret");
        assert_eq!(items[0].attributes.get("user").unwrap(), "alice@gmail.com");
    }
}
