#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod rstb;
mod sarc;
mod util;
mod yaml;

use std::env;
use ::rstb::ResourceSizeTable;
use botw_utils::{extensions::*, hashes::StockHashTable};
use msyt::Msyt;
use roead::{aamp::ParameterIO, byml::Byml, sarc::Sarc};
use serde::Serialize;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Mutex};
use clap::{Command, Arg};

type Result<T> = std::result::Result<T, AppError>;
type State<'a> = tauri::State<'a, Mutex<AppState<'static>>>;

#[derive(Debug, Serialize)]
struct AppError {
    message: String,
    backtrace: String,
}

impl<S> From<S> for AppError
where
    S: AsRef<str>,
{
    fn from(message: S) -> Self {
        let trace = backtrace::Backtrace::new();
        AppError {
            message: message.as_ref().to_owned(),
            backtrace: format!("{:?}", trace),
        }
    }
}

#[derive(Debug)]
struct AppState<'a> {
    open_sarc: Option<Sarc<'a>>,
    hash_table: Option<StockHashTable>,
    open_rstb: Option<Rstb>,
    name_table: HashMap<u32, String>,
    open_yml: Option<Yaml>,
}

#[derive(Debug, Clone, PartialEq)]
struct Rstb {
    table: ResourceSizeTable,
    endian: ::rstb::Endian,
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Yaml {
    endian: YamlEndian,
    doc: YamlDoc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum YamlEndian {
    Big,
    Little,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum YamlDoc {
    Aamp(ParameterIO),
    Byml(Byml),
    Msbt(Msyt),
}

#[tauri::command]
pub(crate) fn has_args() -> bool {
    std::env::args().filter(|arg| arg != "--debug").count() > 1
}

#[tauri::command(async)]
pub(crate) fn open_args(state: State<'_>) -> Value {
    let args = std::env::args();
    if let Some(file) = args.filter(|f| f != "--debug").nth(1) {
        if let Some(ext) = std::path::Path::new(&file)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            if AAMP_EXTS.contains(&ext) || BYML_EXTS.contains(&ext) || ext == "msbt" {
                if let Ok(yaml) = yaml::open_yaml(state, file.clone()) {
                    return json!({
                        "type": "yaml",
                        "data": yaml,
                        "path": file,
                    });
                }
            } else if SARC_EXTS.contains(&ext) {
                if let Ok(sarc) = sarc::open_sarc(state, file.clone()) {
                    return json!({
                        "type": "sarc",
                        "data": sarc,
                        "path": file,
                    });
                }
            } else if ext.ends_with("sizetable") {
                if let Ok(rstb) = rstb::open_rstb(state, file.clone()) {
                    return json!({
                        "type": "rstb",
                        "data": rstb,
                        "path": file,
                    });
                }
            }
        }
    }
    Default::default()
}

fn gui_command() {
    let data_dir = tauri::api::path::config_dir().unwrap().join("wildbits");
    let name_file = data_dir.join("names.json");
    let name_table = match std::fs::read_to_string(name_file)
        .map_err(|e| AppError::from(format!("Failed to open name table: {:?}", e)))
        .and_then(|names| {
            serde_json::from_str::<std::collections::HashMap<u32, String>>(&names)
                .map_err(|e| AppError::from(format!("Failed to parse name table: {:?}", e)))
        }) {
        Ok(name_table) => ::rstb::json::STOCK_NAMES
            .iter()
            .chain(name_table.iter())
            .map(|(k, v)| (*k, v.clone()))
            .collect(),
        Err(e) => {
            println!("Failed to load custom name table: {:?}", e);
            ::rstb::json::STOCK_NAMES.clone()
        }
    };
    tauri::Builder::default()
        .manage(Mutex::new(AppState {
            open_rstb: None,
            name_table,
            open_sarc: None,
            hash_table: None,
            open_yml: None,
        }))
        .invoke_handler(tauri::generate_handler![
            rstb::open_rstb,
            rstb::save_rstb,
            rstb::export_rstb,
            rstb::calc_size,
            rstb::set_size,
            rstb::delete_entry,
            rstb::add_name,
            rstb::scan_mod,
            rstb::flush_names,
            sarc::open_sarc,
            sarc::create_sarc,
            sarc::save_sarc,
            sarc::get_file_meta,
            sarc::add_file,
            sarc::delete_file,
            sarc::update_folder,
            sarc::extract_sarc,
            sarc::extract_file,
            sarc::rename_file,
            sarc::open_sarc_yaml,
            yaml::open_yaml,
            yaml::save_yaml,
            has_args,
            open_args
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn extract_sarc_command(file: String, outdir: String) {
  let res = sarc::open_sarc_local(file, outdir);
  match res {
      Ok(res) => {
            // println!("Result value type: {}", res);
            // Process the successful result value
        }
        Err(err) => {
            println!("Result error type: {:?}", err);
            // Handle the error
        }
    }
}

fn extract_yml_command(file: String, out: String) {
  let res = yaml::open_yaml_local(file, out);
  match res {
      Ok(res) => {
            // println!("Result value type: {}", res);
            // Process the successful result value
        }
        Err(err) => {
            println!("Result error type: {:?}", err);
            // Handle the error
        }
    }
}

fn compress_yml_command(original: String, file: String, out: String) {
  let res = yaml::compress_yaml_local(original, file, out);
  match res {
      Ok(res) => {
            // println!("Result value type: {}", res);
            // Process the successful result value
        }
        Err(err) => {
            println!("Result error type: {:?}", err);
            // Handle the error
        }
    }
}

fn compress_sarc_command(original: String, folder: String, out: String) {
  let res = sarc::compress_sarc_local(original, folder, out);
  match res {
      Ok(res) => {
            // println!("Result value type: {}", res);
            // Process the successful result value
        }
        Err(err) => {
            println!("Result error type: {:?}", err);
            // Handle the error
        }
    }
}

fn main() {
    let matches = Command::new("Switch File Toolkit")
        .about("Toolkit ( including original gui ) to extract / compress switch mod files")
        .subcommand(
            Command::new("gui")
                .about("Launch the original GUI")
        )
        .subcommand(
            Command::new("extract_sarc")
                .about("Extract SARC file")
                .arg(
                    clap::Arg::new("file")
                        .help("The SARC file to extract")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("outdir")
                        .help("The output directory")
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("extract_yml")
                .about("Extract compressed YAML file")
                .arg(
                    Arg::new("file")
                        .help("The compressed YAML file to extract")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("out")
                        .help("The output YAML file")
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("compress_yml")
                .about("Compress YAML file")
                .arg(
                    Arg::new("original")
                        .help("The original byml file")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("file")
                        .help("The uncompressed YAML file to compress")
                        .required(true)
                        .index(2),
                )
                .arg(
                    Arg::new("out")
                        .help("The output compressed YAML file")
                        .required(true)
                        .index(3),
                ),
        )
        .subcommand(
            Command::new("compress_sarc")
                .about("Compress SARC file")
                .arg(
                    Arg::new("original")
                        .help("The original pack file")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("diff_folder")
                        .help("The folder of mod diffs")
                        .required(true)
                        .index(2),
                )
                .arg(
                    Arg::new("out")
                        .help("The output compressed SARC file")
                        .required(true)
                        .index(3),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("gui", _)) => gui_command(),
        Some(("extract_sarc", matches)) => {
            let file = matches.get_one::<String>("file").unwrap();
            let outdir = matches.get_one::<String>("outdir").unwrap();
            extract_sarc_command(file.to_owned(), outdir.to_owned());
        }
        Some(("extract_yml", matches)) => {
            let file = matches.get_one::<String>("file").unwrap();
            let out = matches.get_one::<String>("out").unwrap();
            extract_yml_command(file.to_owned(), out.to_owned());
        }
        Some(("compress_yml", matches)) => {
            let original = matches.get_one::<String>("original").unwrap();
            let file = matches.get_one::<String>("file").unwrap();
            let out = matches.get_one::<String>("out").unwrap();
            compress_yml_command(original.to_owned(), file.to_owned(), out.to_owned());
        }
        Some(("compress_sarc", matches)) => {
            let original = matches.get_one::<String>("original").unwrap();
            let diff_folder = matches.get_one::<String>("diff_folder").unwrap();
            let out = matches.get_one::<String>("out").unwrap();
            compress_sarc_command(original.to_owned(), diff_folder.to_owned(), out.to_owned());
        }
        _ => {
            println!("Invalid command. Use 'help' for available commands.");
        }
    }
}
