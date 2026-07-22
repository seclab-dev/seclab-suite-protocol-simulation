use anyhow::{Context, bail};
use flate2::read::GzDecoder;
use prost::Message;
use serde_json::json;
use std::io::{Cursor, Read};

#[derive(Clone, PartialEq, Message)]
pub struct SimRuleProto {
    #[prost(int64, tag = "1")]
    pub id: i64,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub name_en: String,
    #[prost(string, optional, tag = "4")]
    pub cve: Option<String>,
    #[prost(string, tag = "5")]
    pub category: String,
    #[prost(string, tag = "6")]
    pub description_zh: String,
    #[prost(string, tag = "7")]
    pub description_en: String,
    #[prost(string, tag = "8")]
    pub protocol: String,
    #[prost(int64, optional, tag = "9")]
    pub default_port: Option<i64>,
    #[prost(string, tag = "10")]
    pub config_json: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RulePackageManifestProto {
    #[prost(string, tag = "1")]
    pub package_id: String,
    #[prost(string, tag = "2")]
    pub version: String,
    #[prost(int32, tag = "3")]
    pub ruleset_format_version: i32,
    #[prost(string, tag = "4")]
    pub min_seclab_version: String,
    #[prost(int64, tag = "5")]
    pub generated_at: i64,
    #[prost(int32, tag = "6")]
    pub rule_count: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct SimRulePackageProto {
    #[prost(message, optional, tag = "1")]
    pub manifest: Option<RulePackageManifestProto>,
    #[prost(message, repeated, tag = "2")]
    pub rules: Vec<SimRuleProto>,
}

#[derive(Debug, Clone)]
pub struct ImportedRule {
    pub id: String,
    pub name: String,
    pub name_en: String,
    pub protocol: String,
    pub default_port: u16,
    pub config_json: String,
}

#[derive(Debug, Clone)]
pub struct ImportedRulePackage {
    pub package_id: String,
    pub version: String,
    pub ruleset_format_version: i64,
    pub min_seclab_version: String,
    pub generated_at: String,
    pub rules: Vec<ImportedRule>,
}

pub fn parse_slrp(bytes: &[u8]) -> anyhow::Result<ImportedRulePackage> {
    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(bytes)));
    let mut rules_bin = None;
    let mut has_signature = false;

    for entry in archive
        .entries()
        .context("failed to read rule package archive")?
    {
        let mut entry = entry.context("failed to read rule package entry")?;
        let path = entry
            .path()
            .context("failed to read rule package entry path")?
            .to_string_lossy()
            .replace('\\', "/");
        if path == "rules.bin" {
            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .context("failed to read rules.bin")?;
            rules_bin = Some(content);
        } else if path == "rules.bin.sig" {
            has_signature = true;
        }
    }

    let Some(rules_bin) = rules_bin else {
        bail!("rules.bin is missing from rule package");
    };
    if !has_signature {
        bail!("rules.bin.sig is missing from rule package");
    }

    let package = SimRulePackageProto::decode(rules_bin.as_slice())
        .context("failed to decode rule package payload")?;
    let manifest = package
        .manifest
        .context("rule package manifest is missing")?;
    if manifest.rule_count != package.rules.len() as i32 {
        bail!(
            "rule package manifest declares {} rules but payload contains {}",
            manifest.rule_count,
            package.rules.len()
        );
    }

    let generated_at = chrono::DateTime::from_timestamp(manifest.generated_at, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();
    let mut rules = Vec::with_capacity(package.rules.len());
    for rule in package.rules {
        let default_port = rule
            .default_port
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or_else(|| default_port_for_protocol(&rule.protocol));
        let behavior = serde_json::from_str::<serde_json::Value>(&rule.config_json)
            .with_context(|| format!("rule {} config_json is invalid JSON", rule.id))?;
        let config_json = serde_json::to_string_pretty(&json!({
            "nameEn": rule.name_en.clone(),
            "category": rule.category,
            "cve": rule.cve,
            "description": rule.description_zh,
            "descriptionEn": rule.description_en,
            "behavior": behavior
        }))?;
        rules.push(ImportedRule {
            id: format!("sim-rule-{}", rule.id),
            name: rule.name,
            name_en: rule.name_en,
            protocol: rule.protocol,
            default_port,
            config_json,
        });
    }

    Ok(ImportedRulePackage {
        package_id: manifest.package_id,
        version: manifest.version,
        ruleset_format_version: i64::from(manifest.ruleset_format_version),
        min_seclab_version: manifest.min_seclab_version,
        generated_at,
        rules,
    })
}

fn default_port_for_protocol(protocol: &str) -> u16 {
    match protocol {
        "http" => 80,
        "redis" => 6379,
        "smtp" => 25,
        "pop3" => 110,
        "imap" => 143,
        "ssh" => 22,
        "ftp" => 21,
        "rdp" => 3389,
        _ => 8080,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    #[test]
    fn parse_slrp_decodes_rules_payload() {
        let package = SimRulePackageProto {
            manifest: Some(RulePackageManifestProto {
                package_id: "seclab-sim-rules".to_string(),
                version: "0.1.0-alpha.1".to_string(),
                ruleset_format_version: 1,
                min_seclab_version: "0.1.0-alpha.1".to_string(),
                generated_at: 1_700_000_000,
                rule_count: 1,
            }),
            rules: vec![SimRuleProto {
                id: 100001,
                name: "测试规则".to_string(),
                name_en: "Test Rule".to_string(),
                cve: Some("CVE-2024-0001".to_string()),
                category: "cve_sim".to_string(),
                description_zh: "描述".to_string(),
                description_en: "Description".to_string(),
                protocol: "http".to_string(),
                default_port: Some(8080),
                config_json: r#"{"html":"ok"}"#.to_string(),
            }],
        };
        let mut payload = Vec::new();
        package.encode(&mut payload).unwrap();
        let mut archive_bytes = Vec::new();
        {
            let encoder = GzEncoder::new(&mut archive_bytes, Compression::default());
            let mut tar = Builder::new(encoder);
            append_bytes(&mut tar, "rules.bin", &payload);
            append_bytes(&mut tar, "rules.bin.sig", b"signature");
            tar.finish().unwrap();
        }

        let parsed = parse_slrp(&archive_bytes).unwrap();

        assert_eq!(parsed.package_id, "seclab-sim-rules");
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].id, "sim-rule-100001");
        assert_eq!(parsed.rules[0].name, "测试规则");
        assert_eq!(parsed.rules[0].name_en, "Test Rule");
        assert!(
            parsed.rules[0]
                .config_json
                .contains(r#""nameEn": "Test Rule""#)
        );
        assert!(parsed.rules[0].config_json.contains("CVE-2024-0001"));
    }

    fn append_bytes<W: std::io::Write>(tar: &mut Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, bytes).unwrap();
    }
}
