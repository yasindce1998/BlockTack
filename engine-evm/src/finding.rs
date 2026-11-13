use serde::Serialize;

/// A BlockTack finding, mirroring the Go `core.Finding` JSON shape.
#[derive(Serialize, Clone)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub confidence: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub layer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub weakness: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub evidence: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
}

impl Finding {
    pub fn new(id: impl Into<String>, title: impl Into<String>, severity: impl Into<String>) -> Self {
        Finding {
            id: id.into(),
            title: title.into(),
            severity: severity.into(),
            confidence: String::new(),
            layer: String::new(),
            weakness: String::new(),
            description: String::new(),
            evidence: String::new(),
            target: String::new(),
            source: "engine-evm".to_string(),
        }
    }

    pub fn with(mut self, key: &str, value: impl Into<String>) -> Self {
        let v = value.into();
        let v = if v.is_empty() { None } else { Some(v) };
        if let Some(v) = v {
            match key {
                "confidence" => self.confidence = v,
                "layer" => self.layer = v,
                "weakness" => self.weakness = v,
                "description" => self.description = v,
                "evidence" => self.evidence = v,
                "target" => self.target = v,
                "source" => self.source = v,
                _ => {}
            }
        }
        self
    }
}
