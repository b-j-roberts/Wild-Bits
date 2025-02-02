use crate::{util, AppError, AppState, Result, State};
use botw_utils::{
    extensions::{AAMP_EXTS, BYML_EXTS},
    hashes::{Platform, StockHashTable},
};

use roead::{
    sarc::{Sarc, SarcWriter},
    Endian,
};
use serde_json::{json, Map, Value};
use std::{
    borrow::{Borrow, Cow},
    collections::HashSet,
    fs,
    path::PathBuf,
    sync::Mutex,
};

pub(crate) fn open_sarc_local(file: String, folder: String) -> Result<Value> {
    // Read
    let data = fs::read(file).map_err(|_| AppError::from("Failed to read file"))?;
    let data = util::decompress_if(&data);
    let data = data.to_vec();

    // Parse
    let sarc: Sarc = Sarc::new::<Vec<u8>>(data.into()).map_err(|_| AppError::from("Could not read SARC"))?;
    let hash_table = StockHashTable::new(&match sarc.endian() {
        Endian::Big => Platform::WiiU,
        Endian::Little => Platform::Switch,
    });
    let (tree, modified) = create_tree(&sarc, &hash_table)
        .map_err(|e| AppError::from(format!("Failed to make tree: {:?}", e)))?;
    let res = json!({
        "modded": modified,
        "sarc": Value::Object(tree),
        "be": matches!(sarc.endian(), Endian::Big)
    });
    
    let folder = PathBuf::from(folder);
    sarc
        .files()
        .try_for_each(|file| -> Result<()> {
            let dest = folder.join(file.name().unwrap());
            fs::create_dir_all(dest.parent().unwrap())
                .map_err(|_| AppError::from("Failed to create folder"))?;
            fs::write(folder.join(file.name().unwrap()), file.data())
                .map_err(|e| AppError::from(format!("Failed to write file: {:?}", e)))?;
            Ok(())
        });

   Ok(res)
}

// TODO: Find a way to do it without the original?
pub(crate) fn compress_sarc_local(original: String, folder: String, out: String) -> Result<Value>  {
  let data = fs::read(original).map_err(|_| AppError::from("Failed to read file"))?;
  let data = util::decompress_if(&data);
  let data = data.to_vec();

  let sarc: Sarc = Sarc::new::<Vec<u8>>(data.into()).map_err(|_| AppError::from("Could not read SARC"))?;
  let hash_table = StockHashTable::new(&match sarc.endian() {
      Endian::Big => Platform::WiiU,
      Endian::Little => Platform::Switch,
  });
  let (tree, modified) = create_tree(&sarc, &hash_table)
      .map_err(|e| AppError::from(format!("Failed to make tree: {:?}", e)))?;
  let res = json!({
      "modded": modified,
      "sarc": Value::Object(tree),
      "be": matches!(sarc.endian(), Endian::Big)
  });

  // update_folder
  let folder = PathBuf::from(&folder);
  let mut new_sarc = SarcWriter::from(&sarc);
  glob::glob(folder.join("**/*.*").as_os_str().to_str().unwrap())
        .unwrap()
        .filter_map(|f| f.ok())
        .try_for_each(|file| -> Result<()> {
            let path = file.strip_prefix(&folder).unwrap();
            let data = fs::read(&file).map_err(|_| AppError::from("Failed to read file"))?;
            new_sarc.add_file(&path.to_str().unwrap().replace('\\', "/"), data);
            Ok(())
        })?;
  let sarc: Sarc = Sarc::new::<Vec<u8>>(new_sarc.to_binary().into()).map_err(|_| AppError::from("Could not read SARC"))?;

  // Save_sarc
  let out = PathBuf::from(out);
  let mut writer = SarcWriter::from(&sarc);
  let data = writer.to_binary();
  fs::write(&out, {
      if util::should_compress(&out) {
          util::compress(&data)
      } else {
          data
      }
  })
  .map_err(|_| AppError::from("Failed to write SARC file"))?;


  Ok(res)
}

fn create_tree(
    sarc: &Sarc,
    hash_table: &StockHashTable,
) -> Result<(Map<String, Value>, HashSet<String>)> {
    let mut modified_files: HashSet<String> = HashSet::new();
    let mut tree: Map<String, Value> = Map::new();
    let start_slash = sarc.files().any(|f| f.name().unwrap().starts_with('/'));
    for file in sarc.files() {
        if let Some(name) = file.name() {
            let name = name.trim_start_matches('/');
            if hash_table.is_file_modded(&name.replace(".s", "."), file.data(), true) {
                modified_files.insert(name.to_string());
            }
            let mut path_parts: Vec<String> = name.split('/').map(|p| p.to_owned()).collect();
            if start_slash {
                path_parts.first_mut().unwrap().insert(0, '/');
            }
            let magic = &file.data()[0..4];
            let mut nest_tree: Map<String, Value> = Map::new();
            if magic == b"SARC" || (magic == b"Yaz0" && &file.data()[0x11..0x15] == b"SARC") {
                let nest_sarc = Sarc::new(file.data())
                    .map_err(|_| AppError::from("Could not read nested SARC"))?;
                let result = create_tree(&nest_sarc, hash_table)?;
                nest_tree.extend(result.0.iter().map(|(s, v)| (s.to_owned(), v.clone())));
                modified_files.extend(result.1);
            }
            tree_merge(
                &mut tree,
                &path_parts.iter().rev().fold(nest_tree, |res, cur| {
                    let mut map: Map<String, Value> = Map::new();
                    map.insert(cur.to_string(), Value::Object(res));
                    map
                }),
            );
        }
    }
    Ok((tree, modified_files))
}

#[tauri::command(async)]
pub(crate) fn open_sarc(state: State<'_>, file: String) -> Result<Value> {
    let data = fs::read(file).map_err(|_| AppError::from("Failed to read file"))?;
    let data = util::decompress_if(&data);
    parse_sarc(state, data.to_vec())
}

#[tauri::command]
pub(crate) fn create_sarc(state: State<'_>, big_endian: bool, alignment: u8) -> Result<Value> {
    let mut sarc = SarcWriter::new(if big_endian {
        Endian::Big
    } else {
        Endian::Little
    });
    sarc.set_min_alignment(alignment.into());
    parse_sarc(state, sarc.to_binary())
}

#[tauri::command(async)]
pub(crate) fn save_sarc(state: State<'_>, file: String) -> Result<()> {
    let file = PathBuf::from(file);
    let mut writer = SarcWriter::from(state.lock().unwrap().open_sarc.as_ref().unwrap());
    let data = writer.to_binary();
    fs::write(&file, {
        if util::should_compress(&file) {
            util::compress(&data)
        } else {
            data
        }
    })
    .map_err(|_| AppError::from("Failed to write SARC file"))?;
    Ok(())
}

#[tauri::command]
pub(crate) fn get_file_meta(
    state: tauri::State<'_, Mutex<AppState<'static>>>,
    file: String,
) -> Result<Value> {
    let state = state.lock().unwrap();
    let sarc = state.open_sarc.as_ref().unwrap();
    let data = open_nested_file(sarc, &file)?;
    let path = PathBuf::from(&file);
    let ext = path.extension().unwrap().to_str().unwrap();
    Ok(json!({
        "file": path.file_name().unwrap().to_str().unwrap(),
        "rstb": ::rstb::calc::calculate_size_with_ext(
            &data,
            ext,
            match sarc.endian() {
                Endian::Big => ::rstb::Endian::Big,
                Endian::Little => ::rstb::Endian::Little,
            },
            true,
        ),
        "size": data.len(),
        "modified": state.hash_table.as_ref().unwrap().is_file_modded(file.replace(".s", "."), data, true),
        "is_yaml": AAMP_EXTS.contains(&ext) || BYML_EXTS.contains(&ext) || ext == "msbt"
    }))
}

#[tauri::command]
pub(crate) fn add_file(state: State<'_>, file: String, path: String) -> Result<Value> {
    let path = path.trim_end_matches('/').replace("SARC:", "");
    let levels: Vec<&str> = path.split("//").collect();
    let filename = *levels.last().unwrap();
    let data = fs::read(file).map_err(|_| AppError::from("Failed to read file"))?;
    modify_sarc(state, &path, |sw| {
        sw.add_file(filename, data);
    })
}

#[tauri::command]
pub(crate) fn delete_file(state: State<'_>, path: String) -> Result<Value> {
    let path = path.trim_end_matches('/').replace("SARC:", "");
    let levels: Vec<&str> = path.split("//").collect();
    let filename = *levels.last().unwrap();
    modify_sarc(state, &path, |sw| {
        sw.remove_file(filename);
    })
}

#[tauri::command(async)]
pub(crate) fn update_folder(state: State<'_>, folder: String) -> Result<Value> {
    let folder = PathBuf::from(&folder);
    let mut new_sarc = SarcWriter::from(state.lock().unwrap().open_sarc.as_ref().unwrap());
    glob::glob(folder.join("**/*.*").as_os_str().to_str().unwrap())
        .unwrap()
        .filter_map(|f| f.ok())
        .try_for_each(|file| -> Result<()> {
            let path = file.strip_prefix(&folder).unwrap();
            let data = fs::read(&file).map_err(|_| AppError::from("Failed to read file"))?;
            new_sarc.add_file(&path.to_str().unwrap().replace('\\', "/"), data);
            Ok(())
        })?;
    parse_sarc(state, new_sarc.to_binary())
}

#[tauri::command(async)]
pub(crate) fn extract_sarc(state: State<'_>, folder: String) -> Result<()> {
    let folder = PathBuf::from(folder);
    state
        .lock()
        .unwrap()
        .open_sarc
        .as_ref()
        .unwrap()
        .files()
        .try_for_each(|file| -> Result<()> {
            let dest = folder.join(file.name().unwrap());
            fs::create_dir_all(dest.parent().unwrap())
                .map_err(|_| AppError::from("Failed to create folder"))?;
            fs::write(folder.join(file.name().unwrap()), file.data())
                .map_err(|e| AppError::from(format!("Failed to write file: {:?}", e)))?;
            Ok(())
        })
}

#[tauri::command]
pub(crate) fn extract_file(state: State<'_>, file: String, path: String) -> Result<()> {
    let state = state.lock().unwrap();
    let data = open_nested_file(state.open_sarc.as_ref().unwrap(), &path)?;
    fs::write(file, data).map_err(|_| AppError::from("Failed to extract file"))?;
    Ok(())
}

#[tauri::command]
pub(crate) fn rename_file(state: State<'_>, path: String, new_path: String) -> Result<Value> {
    let path = path.trim_end_matches('/').replace("SARC:", "");
    let levels: Vec<&str> = path.split("//").collect();
    let filename = *levels.last().unwrap();
    let state_lock = state.lock().unwrap();
    let data = state_lock
        .open_sarc
        .as_ref()
        .unwrap()
        .get_data(filename)
        .unwrap()
        .to_owned();
    drop(state_lock);
    modify_sarc(state, &path, |sw| {
        sw.add_file(
            &PathBuf::from(filename)
                .parent()
                .unwrap()
                .join(new_path)
                .to_str()
                .unwrap()
                .replace('\\', "/"),
            data,
        );
    })
}

#[tauri::command]
pub(crate) fn open_sarc_yaml(state: State<'_>, path: String) -> Result<Value> {
    let state_lock = state.lock().unwrap();
    let data = open_nested_file(state_lock.open_sarc.as_ref().unwrap(), &path)?.to_vec();
    drop(state_lock);
    crate::yaml::parse_yaml(state, &data)
}

pub(crate) fn parse_sarc<I: Into<Vec<u8>>>(state: State<'_>, data: I) -> Result<Value> {
    let sarc: Sarc = Sarc::new(data.into()).map_err(|_| AppError::from("Could not read SARC"))?;
    let hash_table = StockHashTable::new(&match sarc.endian() {
        Endian::Big => Platform::WiiU,
        Endian::Little => Platform::Switch,
    });
    let (tree, modified) = create_tree(&sarc, &hash_table)
        .map_err(|e| AppError::from(format!("Failed to make tree: {:?}", e)))?;
    let res = json!({
        "modded": modified,
        "sarc": Value::Object(tree),
        "be": matches!(sarc.endian(), Endian::Big)
    });
    state.lock().unwrap().hash_table = Some(hash_table);
    state.lock().unwrap().open_sarc = Some(sarc);
    util::DECOMP_MAP.lock().unwrap().clear();
    Ok(res)
}

pub(crate) fn modify_sarc<F: FnOnce(&mut SarcWriter)>(
    state: State<'_>,
    path: &str,
    task: F,
) -> Result<Value> {
    let state_lock = state.lock().unwrap();
    let open_sarc = state_lock.open_sarc.as_ref().unwrap();
    let mut parent = get_parent_sarc(open_sarc, path)?;
    let mut new_sarc = SarcWriter::from(parent.borrow());
    task(&mut new_sarc);
    while Cow::Borrowed(open_sarc) != parent {
        let child = new_sarc.to_binary();
        let sub_path: &str = path[..path.rfind("//").unwrap()].trim_end_matches('/');
        parent = get_parent_sarc(open_sarc, sub_path)?;
        new_sarc = SarcWriter::from(parent.borrow());
        new_sarc.add_file(
            sub_path,
            if util::should_compress(sub_path) {
                util::compress(child)
            } else {
                child
            },
        );
    }
    drop(state_lock);
    parse_sarc(state, new_sarc.to_binary())
}

fn get_parent_sarc<'a>(sarc: &'a Sarc<'a>, file: &str) -> Result<Cow<'a, Sarc<'a>>> {
    let levels: Vec<&str> = file.split("//").collect();
    if levels.len() == 1 {
        Ok(Cow::Borrowed(sarc))
    } else {
        let data = open_nested_file(sarc, levels[..levels.len() - 1].join("//").as_str())?;
        Ok(Cow::Owned(
            Sarc::new(util::decompress_if(&data).to_vec())
                .map_err(|e| AppError::from(format!("Failed to get parent SARC: {:?}", e)))?,
        ))
    }
}

fn open_nested_file<'a, 'b>(sarc: &'a Sarc, file: &'b str) -> Result<Cow<'a, [u8]>> {
    let file = file.trim_start_matches("SARC:");
    let levels: Vec<&str> = file.split("//").collect();
    if levels.len() == 1 {
        Ok(Cow::from(
            sarc.get_data(file.trim_end_matches('/'))
                .ok_or_else(|| AppError::from("File doesn't exist"))?,
        ))
    } else {
        let parent = levels[0..levels.len() - 1].join("//");
        let next_data = open_nested_file(sarc, parent.as_str())?;
        let next_sarc = Sarc::new(util::decompress_if(next_data.as_ref()).to_vec())
            .map_err(|e| AppError::from(format!("Failed to parse SARC: {:?}", e)))?;
        let final_data = open_nested_file(
            unsafe {
                /* Force the compiler to accept that references to file data
                in nested SARCs have the same lifetime as the root SARC */
                std::mem::transmute::<&Sarc<'_>, &Sarc<'a>>(&next_sarc)
            },
            &levels[1..].join("//"),
        )?;
        if &next_data[0..4] == b"Yaz0" {
            let final_data = Vec::from(final_data);
            Ok(final_data.into())
        } else {
            Ok(final_data)
        }
    }
}

fn tree_merge(dict: &mut serde_json::Map<String, Value>, dict2: &serde_json::Map<String, Value>) {
    for key in dict2.keys() {
        if dict.contains_key(key) && dict[key].is_object() && dict2[key].is_object() {
            tree_merge(
                dict.get_mut(key).unwrap().as_object_mut().unwrap(),
                dict2[key].as_object().unwrap(),
            );
        } else if dict.contains_key(key) && dict[key].is_array() && dict2[key].is_array() {
            dict[key]
                .as_array_mut()
                .unwrap()
                .extend(dict2[key].as_array().unwrap().iter().cloned());
        } else {
            dict.insert(key.to_owned(), dict2[key].clone());
        }
    }
}
