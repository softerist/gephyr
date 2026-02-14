use sysinfo::System;
fn get_current_exe_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
}
fn get_process_info() -> (Option<std::path::PathBuf>, Option<Vec<String>>) {
    let mut system = System::new_all();
    system.refresh_all();

    let current_exe = get_current_exe_path();
    let current_pid = std::process::id();

    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        if pid_u32 == current_pid {
            continue;
        }
        if let (Some(ref my_path), Some(p_exe)) = (&current_exe, process.exe()) {
            if let Ok(p_path) = p_exe.canonicalize() {
                if my_path == &p_path {
                    continue;
                }
            }
        }

        let name = process.name().to_string_lossy().to_lowercase();
        if let Some(exe) = process.exe() {
            let mut args = process.cmd().iter();
            let exe_path = args
                .next()
                .map_or(exe.to_string_lossy(), |arg| arg.to_string_lossy())
                .to_lowercase();
            let args = args
                .map(|arg| arg.to_string_lossy().to_lowercase())
                .collect::<Vec<String>>();

            let args_str = args.join(" ");
            let is_helper = args_str.contains("--type=")
                || args_str.contains("node-ipc")
                || args_str.contains("nodeipc")
                || args_str.contains("max-old-space-size")
                || args_str.contains("node_modules")
                || name.contains("helper")
                || name.contains("plugin")
                || name.contains("renderer")
                || name.contains("gpu")
                || name.contains("crashpad")
                || name.contains("utility")
                || name.contains("audio")
                || name.contains("sandbox")
                || exe_path.contains("crashpad");

            let path = Some(exe.to_path_buf());
            let args = Some(args);
            #[cfg(target_os = "macos")]
            {
                if exe_path.contains("antigravity.app")
                    && !is_helper
                    && !exe_path.contains("frameworks")
                {
                    if let Some(app_idx) = exe_path.find(".app") {
                        let app_path_str = &exe.to_string_lossy()[..app_idx + 4];
                        let path = Some(std::path::PathBuf::from(app_path_str));
                        return (path, args);
                    }
                    return (path, args);
                }
            }

            #[cfg(target_os = "windows")]
            {
                if name == "antigravity.exe" && !is_helper {
                    return (path, args);
                }
            }

            #[cfg(target_os = "linux")]
            {
                if (name == "antigravity" || exe_path.contains("/antigravity"))
                    && !name.contains("tools")
                    && !is_helper
                {
                    return (path, args);
                }
            }
        }
    }
    (None, None)
}
pub fn get_path_from_running_process() -> Option<std::path::PathBuf> {
    let (path, _) = get_process_info();
    path
}
pub fn get_args_from_running_process() -> Option<Vec<String>> {
    let (_, args) = get_process_info();
    args
}
pub fn get_user_data_dir_from_process() -> Option<std::path::PathBuf> {
    if let Ok(config) = crate::modules::system::config::load_app_config() {
        if let Some(args) = config.antigravity_args {
            for i in 0..args.len() {
                if args[i] == "--user-data-dir" && i + 1 < args.len() {
                    let path = std::path::PathBuf::from(&args[i + 1]);
                    if path.exists() {
                        return Some(path);
                    }
                } else if args[i].starts_with("--user-data-dir=") {
                    let parts: Vec<&str> = args[i].splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let path_str = parts[1];
                        let path = std::path::PathBuf::from(path_str);
                        if path.exists() {
                            return Some(path);
                        }
                    }
                }
            }
        }
    }
    if let Some(args) = get_args_from_running_process() {
        for i in 0..args.len() {
            if args[i] == "--user-data-dir" && i + 1 < args.len() {
                let path = std::path::PathBuf::from(&args[i + 1]);
                if path.exists() {
                    return Some(path);
                }
            } else if args[i].starts_with("--user-data-dir=") {
                let parts: Vec<&str> = args[i].splitn(2, '=').collect();
                if parts.len() == 2 {
                    let path_str = parts[1];
                    let path = std::path::PathBuf::from(path_str);
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}
pub fn get_antigravity_executable_path() -> Option<std::path::PathBuf> {
    if let Some(path) = get_path_from_running_process() {
        return Some(path);
    }
    check_standard_locations()
}
fn check_standard_locations() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let path = std::path::PathBuf::from("/Applications/Antigravity.app");
        if path.exists() {
            return Some(path);
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::env;
        let local_appdata = env::var("LOCALAPPDATA").ok();
        let program_files =
            env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
        let program_files_x86 =
            env::var("ProgramFiles(x86)").unwrap_or_else(|_| "C:\\Program Files (x86)".to_string());

        let mut possible_paths = Vec::new();
        if let Some(local) = local_appdata {
            possible_paths.push(
                std::path::PathBuf::from(&local)
                    .join("Programs")
                    .join("Antigravity")
                    .join("Antigravity.exe"),
            );
        }
        possible_paths.push(
            std::path::PathBuf::from(&program_files)
                .join("Antigravity")
                .join("Antigravity.exe"),
        );
        possible_paths.push(
            std::path::PathBuf::from(&program_files_x86)
                .join("Antigravity")
                .join("Antigravity.exe"),
        );
        for path in possible_paths {
            if path.exists() {
                return Some(path);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let possible_paths = vec![
            std::path::PathBuf::from("/usr/bin/antigravity"),
            std::path::PathBuf::from("/opt/Antigravity/antigravity"),
            std::path::PathBuf::from("/usr/share/antigravity/antigravity"),
        ];
        if let Some(home) = dirs::home_dir() {
            let user_local = home.join(".local/bin/antigravity");
            if user_local.exists() {
                return Some(user_local);
            }
        }

        for path in possible_paths {
            if path.exists() {
                return Some(path);
            }
        }
    }

    None
}