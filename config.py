import os
import platform
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOL_DIR = os.path.join(BASE_DIR, 'tool')
PLUGINS_DIR = os.path.join(BASE_DIR, 'plugins')
NUCLEI_TEMPLATES_DIR = os.path.join(TOOL_DIR, 'nuclei-templates')

IS_WINDOWS = platform.system() == 'Windows'
_EXE_SUFFIX = '.exe' if IS_WINDOWS else ''


def _find_tool(name):
    """查找工具路径: 优先 tool/ 目录，其次系统 PATH，最后搜索常见安装路径"""
    # 1. tool/<name>/ 目录
    local_path = os.path.join(TOOL_DIR, name, name + _EXE_SUFFIX)
    if os.path.isfile(local_path):
        return local_path
    # 2. tool/ 根目录 (兼容旧布局)
    root_path = os.path.join(TOOL_DIR, name + _EXE_SUFFIX)
    if os.path.isfile(root_path):
        return root_path
    # 3. 系统 PATH
    system_path = shutil.which(name + _EXE_SUFFIX) or shutil.which(name)
    if system_path:
        return system_path
    # 4. Windows 常见安装路径
    if IS_WINDOWS:
        for base in [r'C:\Program Files (x86)\Nmap',
                     r'C:\Program Files\Nmap']:
            p = os.path.join(base, name + _EXE_SUFFIX)
            if os.path.isfile(p):
                return p
    return local_path


NMAP_PATH = _find_tool('nmap')
NUCLEI_PATH = _find_tool('nuclei')

# ========== 数据库配置 ==========
# 设为 'sqlite' 或 'mysql'
DB_TYPE = os.environ.get('DB_TYPE', 'sqlite')

# SQLite 配置 (DB_TYPE=sqlite 时有效)
DATABASE_PATH = os.path.join(BASE_DIR, 'data', 'scanner.db')

# MySQL 配置 (DB_TYPE=mysql 时有效)
MYSQL_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'QQQQaq_xj_scan')
MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE', 'blackbox_scanner')

# ========== Flask ==========
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 5000
FLASK_DEBUG = False
