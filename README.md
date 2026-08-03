# NalTool

A lightweight cross-platform encryption tool.  

---

## English

### Description

NalTool is a lightweight cross-platform encryption tool for text and files.  
It provides both a command-line interface and an interactive interface, suitable for scripting and manual use.  
Written in Rust, it is distributed as a single binary file with no external dependencies.  

### Features

- Encrypt and decrypt text  
- Encrypt and decrypt files  
- Optional Gzip compression (--compress, --level)  
- NalKey key file support for key management  
- Cross-platform support: Windows, Linux, macOS  

### Quick Start

First, download the appropriate executable and installation script from the [Releases](https://github.com/TasKin-tk/NalTool/releases) page.  
Then run the installation script to install NalTool. During installation, the script will ask for the path to the executable; enter the path of the downloaded executable.  

If you cannot find a suitable executable in Releases, try cloning the repository and compiling it manually.  

### Usage Examples

| Command | Description |
|---------|-------------|
| `naltool -v` | Show version information |
| `naltool -i` | Enter interactive interface |
| `naltool -h` | Show help information |
| `naltool -e file.txt -k "key"` | Encrypt a file |
| `naltool -d file.nalfile -k "key"` | Decrypt a file |
| `naltool -e "Hello" --text -k "key"` | Encrypt text |
| `naltool -d "ciphertext" --text -k "key"` | Decrypt text |
| `naltool -e file.txt -n keyfile.nalkey` | Encrypt a file using NalKey |
| `naltool -d file.nalfile -n keyfile.nalkey` | Decrypt a file using NalKey |
| `naltool -e file.txt -c -l 6 -k "key"` | Encrypt with compression |
| `naltool --new` | Generate a new NalKey file |

### Prebuilt Platforms

This repository provides prebuilt executables for the following platforms, located in the `bin` directory:  

- Windows (x86_64)
- macOS (x86_64, aarch64)
- Linux (x86_64, aarch64)

Installation and uninstallation scripts are also provided for Windows and macOS/Linux.  

### License

MIT License  

### Author

TasKin  

GitHub: https://github.com/TasKin-tk  
Email: tnailkogns@hotmail.com  

---

## 中文

### 简介

NalTool 是一款轻量级跨平台加解密工具，支持文本和文件加密。  
同时提供命令行参数和交互式界面，方便脚本调用和手动使用。  
使用 Rust 编写，以单文件二进制形式分发，无需外部依赖。  

### 功能

- 加密和解密文本  
- 加密和解密文件  
- 可选的 Gzip 压缩（--compress, --level）  
- 支持 NalKey 密钥文件管理  
- 跨平台支持：Windows、Linux、macOS  

### 快速开始

请先到 [Releases](https://github.com/TasKin-tk/NalTool/releases) 页面下载合适的可执行文件和安装脚本。  
然后运行安装脚本进行安装。安装时，安装脚本会提示输入可执行文件的路径，输入下载的可执行文件的路径即可。  

如果你没有在 Releases 里找到合适的可执行文件，请尝试克隆仓库后手动编译。  

### 使用示例

| 命令 | 说明 |
|------|------|
| `naltool -v` | 显示版本信息 |
| `naltool -i` | 进入交互界面 |
| `naltool -h` | 显示帮助信息 |
| `naltool -e 文件.txt -k "密钥"` | 加密文件 |
| `naltool -d 文件.nalfile -k "密钥"` | 解密文件 |
| `naltool -e "Hello" --text -k "密钥"` | 加密文本 |
| `naltool -d "密文" --text -k "密钥"` | 解密文本 |
| `naltool -e 文件.txt -n 密钥文件.nalkey` | 使用 NalKey 加密文件 |
| `naltool -d 文件.nalfile -n 密钥文件.nalkey` | 使用 NalKey 解密文件 |
| `naltool -e 文件.txt -c -l 6 -k "密钥"` | 压缩并加密 |
| `naltool --new` | 生成新的 NalKey 文件 |

### 预编译平台

本仓库提供以下平台的预编译可执行文件，存放在 bin 目录下：  

- Windows（x86_64）
- macOS（x86_64、aarch64）
- Linux（x86_64、aarch64）

同时也提供 Windows 和 macOS/Linux 平台的安装与卸载脚本。  

### 开源协议

MIT 协议  

### 作者

TasKin  

GitHub：https://github.com/TasKin-tk  
邮箱：tnailkogns@hotmail.com  
