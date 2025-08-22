use prost_build::Config;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_out = PathBuf::from("prost_tmp");
    fs::create_dir_all(&tmp_out)?;

    let mut config = Config::new();
    config.btree_map(&["."]);
    config.out_dir(&tmp_out);

    config.compile_protos(
        &[
            "src/events/hook/hook.proto",
            "src/events/scanner/scanner.proto",
            "src/events/callbacks/callbacks.proto",
            "src/events/event.proto",
        ],
        &["src/events"],
    )?;

    // Move files to respective folders
    move_generated_file(&tmp_out, "hook.rs", "src/events/hook")?;
    move_generated_file(&tmp_out, "scanner.rs", "src/events/scanner")?;
    move_generated_file(&tmp_out, "callbacks.rs", "src/events/callbacks")?;
    move_generated_file(&tmp_out, "event.rs", "src/events")?;

    if tmp_out.exists() {
        fs::remove_dir_all(&tmp_out)?;
    }

    Ok(())
}

fn move_generated_file(
    from_dir: &Path,
    filename: &str,
    to_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(to_dir)?;
    let from_path = from_dir.join(filename);
    let to_path = Path::new(to_dir).join(filename);

    if !from_path.exists() {
        return Err(format!("Generated file not found: {}", from_path.display()).into());
    }

    fs::copy(&from_path, &to_path)?;
    fs::remove_file(&from_path)?;

    println!("Moved {} -> {}", from_path.display(), to_path.display());
    Ok(())
}
