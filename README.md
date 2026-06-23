# BlackBox Scanner - 黑盒漏洞巡检扫描器

基于 Nmap + Dirsearch + Nuclei 的自动化漏洞巡检系统，提供 Web 管理界面，支持自定义 Nuclei 插件。

## 系统要求

- **操作系统**: Linux x86_64 / Windows 10+ x64
- **Python**: 3.8+
- **依赖工具**: nmap, nuclei, dirsearch, git（可通过脚本自动下载）

---

## 快速开始 (本地 / 短期使用)

默认使用 **SQLite**，无需额外安装数据库，开箱即用。

### 1. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

### 2. 安装扫描工具

```bash
# Linux
sudo apt install -y nmap
cd tool && chmod +x download_tools.sh && ./download_tools.sh && cd ..

# Windows: 手动安装 nmap + 下载 nuclei.exe 放到 tool/nuclei/
# 或运行 tool/download_tools.ps1
```

### 3. 启动

```bash
python app.py
# 浏览器打开 http://localhost:5000
```

启动后会在 `data/` 目录自动创建 `scanner.db`（SQLite）。

---

## 部署到 Linux 服务器 (生产环境)

推荐使用 **MySQL** 作为数据库。

### 1. 安装系统依赖

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip nmap git wget unzip

# CentOS/RHEL
sudo yum install -y python3 python3-pip nmap git wget unzip
```

### 2. 安装 Python 依赖

```bash
cd /opt/blackbox-scanner
pip install -r requirements.txt
```

### 3. 下载 Nuclei

```bash
cd tool
chmod +x download_tools.sh
./download_tools.sh
cd ..
```

### 4. 创建 MySQL 数据库

```sql
CREATE DATABASE blackbox_scanner CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'scanner'@'localhost' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON blackbox_scanner.* TO 'scanner'@'localhost';
FLUSH PRIVILEGES;
```

### 5. 配置环境变量并启动

```bash
export DB_TYPE=mysql
export MYSQL_HOST=127.0.0.1
export MYSQL_PORT=3306
export MYSQL_USER=scanner
export MYSQL_PASSWORD=your_strong_password
export MYSQL_DATABASE=blackbox_scanner

python app.py
# 访问 http://服务器IP:5000
```

### 6. 使用 systemd 常驻后台 (推荐)

创建 `/etc/systemd/system/blackbox-scanner.service`：

```ini
[Unit]
Description=BlackBox Scanner
After=network.target mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/blackbox-scanner
Environment="DB_TYPE=mysql"
Environment="MYSQL_HOST=127.0.0.1"
Environment="MYSQL_PORT=3306"
Environment="MYSQL_USER=scanner"
Environment="MYSQL_PASSWORD=your_strong_password"
Environment="MYSQL_DATABASE=blackbox_scanner"
ExecStart=/usr/bin/python3 /opt/blackbox-scanner/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable blackbox-scanner
sudo systemctl start blackbox-scanner
sudo systemctl status blackbox-scanner
```

---

## 数据库配置说明

通过环境变量切换数据库，无需改代码。

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `DB_TYPE` | `sqlite` | 数据库类型，设为 `sqlite` 或 `mysql` |
| `MYSQL_HOST` | `127.0.0.1` | MySQL 主机地址 (仅 mysql 模式) |
| `MYSQL_PORT` | `3306` | MySQL 端口 (仅 mysql 模式) |
| `MYSQL_USER` | `root` | MySQL 用户名 (仅 mysql 模式) |
| `MYSQL_PASSWORD` | (空) | MySQL 密码 (仅 mysql 模式) |
| `MYSQL_DATABASE` | `blackbox_scanner` | MySQL 数据库名 (仅 mysql 模式) |

### 使用方式

```bash
# SQLite 模式 (默认，无需设置)
python app.py

# MySQL 模式
DB_TYPE=mysql MYSQL_PASSWORD=123456 python app.py

# 或者先 export 再启动
export DB_TYPE=mysql
export MYSQL_PASSWORD=123456
python app.py
```

### 两种模式的表结构

| 模式 | 启动时自动建表 | ID 类型 | 大文本字段 |
|------|---------------|---------|-----------|
| SQLite | `data/scanner.db` | AUTOINCREMENT | TEXT |
| MySQL | `blackbox_scanner` | AUTO_INCREMENT | MEDIUMTEXT |

四种表：`scans`、`vulnerabilities`、`nuclei_plugins`，两种模式结构一致，接口完全兼容。

> **注意**: MySQL 模式下不会生成 `data/scanner.db` 文件，所有数据直接写入 MySQL。

---

## 功能说明

### 仪表盘
展示扫描任务数、发现漏洞数、自定义插件数等概览信息。

### 扫描类型

| 类型 | 流程 | 适用场景 |
|------|------|----------|
| `完整扫描` | Nmap → Dirsearch → Nuclei | IP/域名输入，全流程 |
| `目录扫描` | Nmap → Dirsearch | 仅目录枚举 |
| `仅端口扫描` | Nmap | 快速端口发现 |
| `仅目录扫描` | Dirsearch | URL 输入，目录扫描 |

> **输入模式**：输入纯 IP/域名 → Nmap 端口发现 → 构造 `http(s)://IP:PORT` → Dirsearch/Nuclei；输入 `http://IP:PORT` 格式 → 跳过 Nmap，直接 Dirsearch + Nuclei。

### 扫描管理
- **新建扫描**: 输入目标 IP/域名/URL，选择扫描类型
- **批量上传**: 上传 `.txt` 文件（每行一个目标），弹窗编辑确认后批量扫描
- **批量操作**: 全选扫描历史，支持批量取消排队、批量删除
- **扫描详情**: 实时展示扫描步骤（Nmap → Dirsearch → Nuclei），显示各阶段输出
- **后台队列**: 支持多任务排队扫描

### 漏洞管理
- **漏洞列表**: 按 IP 分组展示，点击 IP 行展开/收起该目标下所有漏洞
- **漏洞详情**: 查看漏洞名称、严重程度、目标 IP、请求/响应包、cURL 复现命令

### 插件管理
- **新建/编辑插件**: 在 Web 页面编写 Nuclei YAML 模板
- **自动加载**: 保存的插件会在下次 Nuclei 扫描时自动同步到 `plugins/` 目录并被加载
- **删除插件**: 不再使用的插件可随时删除

---

## 目录结构

```
blackbox-scanner/
├── app.py                 # Flask 主程序
├── config.py              # 配置文件 (路径/端口/数据库)
├── database.py            # 数据库操作 (SQLite / MySQL 双后端)
├── scanner.py             # 扫描引擎 (Nmap + Dirsearch + Nuclei)
├── requirements.txt       # Python 依赖 (flask + pymysql + dirsearch + setuptools)
├── README.md              # 本文件
├── .gitignore             # Git 忽略规则
├── tool/                  # 扫描工具目录
│   ├── download_tools.sh  # 一键下载脚本 (Linux)
│   ├── download_tools.ps1 # 一键下载脚本 (Windows)
│   ├── nmap/              # nmap 二进制
│   ├── nuclei/            # nuclei 二进制
│   └── nuclei-templates/  # Nuclei 官方模板库
├── plugins/               # 用户自定义插件 (YAML)
├── data/                  # SQLite 数据库 (sqlite 模式)
├── templates/             # Web 页面模板
│   ├── base.html          # 基础布局 (侧边栏 + 竹叶导航)
│   ├── index.html         # 仪表盘 + 扫描历史
│   ├── new_scan.html      # 新建扫描任务
│   ├── scan_detail.html   # 扫描详情 (竹子生长动画)
│   ├── vulnerability_list.html  # 漏洞总览 (IP 分组)
│   └── vulnerability_detail.html # 漏洞详情
└── static/                # CSS/JS 静态资源
```

---

## 自定义 Nuclei 插件示例

在 Web 页面「插件管理」中新建插件，编写符合 Nuclei YAML 规范的模板：

```yaml
id: phpinfo-files
info:
  name: phpinfo Files Detection
  author: admin
  severity: low
  description: Detect exposed phpinfo.php files.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/phpinfo.php"
    matchers:
      - type: word
        words:
          - "phpinfo()"
          - "PHP Version"
        condition: or
```

---

## 注意事项

1. 确保扫描工具（nmap、nuclei、dirsearch）有执行权限
2. 部分扫描操作可能需要 root 权限（如 SYN 扫描）
3. 请遵守法律法规，仅对授权目标进行扫描
4. SQLite 模式下数据库文件位于 `data/scanner.db`，建议定期备份
5. 从 SQLite 迁移到 MySQL：导出 SQLite 数据 → 导入 MySQL → 设置 `DB_TYPE=mysql` 启动即可，表名和字段完全一致
6. **dirsearch 模块**: 需要 `setuptools<68`（新版移除 pkg_resources，可运行 `pip install 'setuptools<68'`）

---

## 更新日志

### v1.1
- 新增 Dirsearch 目录扫描模块
- 新增 4 种扫描类型（full / dirsearch_nmap / nmap / dirsearch）
- Nmap 后自动筛选 HTTP 端口执行 Dirsearch
- Dirsearch 输出仅保留有效发现（过滤 404、进度信息）
- URL 输入模式跳过 Nmap 但不跳过 Dirsearch
- 漏洞列表按 IP 分组，点击展开
- 批量上传 .txt 文件扫描
- 全选 + 批量取消排队 + 批量删除
- 修复文件上传幽灵点击 & 弹窗打开两次问题
- 新增 `.gitignore` 防止敏感文件泄露
