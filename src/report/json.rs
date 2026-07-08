use std::fs::File;
use std::io::Write;
use crate::model::ScanResultSummary;

pub fn save_to_json(summary: &ScanResultSummary, file_path: &str) -> Result<(), String> {
    let json_data = serde_json::to_string_pretty(summary)
        .map_err(|e| format!("Failed to serialize results to JSON: {}", e))?;
    
    let mut file = File::create(file_path)
        .map_err(|e| format!("Failed to create output file '{}': {}", file_path, e))?;
        
    file.write_all(json_data.as_bytes())
        .map_err(|e| format!("Failed to write data to output file: {}", e))?;
        
    Ok(())
}
