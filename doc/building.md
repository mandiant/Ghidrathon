# Building

## Requirements

Tool | Version |Source |
|---|---|---|
| Ghidrathon | `>= 4.0.0` | https://github.com/mandiant/Ghidrathon/releases |
| Ghidra | `>= 10.3.2` | https://github.com/NationalSecurityAgency/ghidra/releases |
| Java | `>= 17.0.0` | https://adoptium.net/temurin/releases/ |
| Gradle | `>= 7.3` | https://gradle.org/releases |

Use the following steps to build Ghidrathon:
1. Download the [supported Jep JAR release](https://github.com/ninia/jep/releases/download/v4.2.0/jep-4.2.0.jar) to `<absolute_path_to_ghidrathon_source_dir>\lib`
2. Execute gradle from `<absolute_path_to_ghidrathon_source_dir>`:
```
$ gradle -PGHIDRA_INSTALL_DIR=<absolute_path_to_Ghidra_install_dir>
```

The extension is stored in `<absolute_path_to_ghidrathon_source_dir>\dist`.
