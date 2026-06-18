#!/bin/bash
# ==============================================
# 黑盒漏洞巡检扫描器 - 工具下载脚本
# 适配: Linux x86_64
# 用法: chmod +x download_tools.sh && ./download_tools.sh
# ==============================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NMAP_DIR="$SCRIPT_DIR/nmap"
NUCLEI_DIR="$SCRIPT_DIR/nuclei"
TEMPLATES_DIR="$SCRIPT_DIR/nuclei-templates"

mkdir -p "$NMAP_DIR" "$NUCLEI_DIR"

echo "========================================="
echo " BlackBox Scanner - 工具下载"
echo "========================================="

# ---------- 1. 下载 Nmap ----------
echo "[1/3] 下载 Nmap..."
NMAP_URL="https://github.com/nmap/nmap/archive/refs/tags/v7.94.tar.gz"
NMAP_ZIP="$SCRIPT_DIR/nmap-src.tar.gz"

if [ -f "$NMAP_DIR/nmap" ]; then
    echo "  Nmap 已存在: $NMAP_DIR/nmap"
else
    if ! command -v nmap &>/dev/null; then
        echo "  系统未安装 nmap，请手动安装："
        echo "    Ubuntu/Debian: sudo apt install -y nmap"
        echo "    CentOS/RHEL:   sudo yum install -y nmap"
        echo "  然后将 nmap 二进制文件复制到 $NMAP_DIR/nmap"
    else
        SYSTEM_NMAP=$(which nmap)
        cp "$SYSTEM_NMAP" "$NMAP_DIR/nmap"
        echo "  -> 已从系统路径复制: $SYSTEM_NMAP"
    fi
fi

# ---------- 2. 下载 Nuclei ----------
echo "[2/3] 下载 Nuclei..."
NUCLEI_VERSION="3.3.9"
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
NUCLEI_ZIP="$SCRIPT_DIR/nuclei.zip"

if [ -f "$NUCLEI_DIR/nuclei" ]; then
    echo "  Nuclei 已存在: $NUCLEI_DIR/nuclei"
else
    echo "  下载 $NUCLEI_URL ..."
    if command -v wget &>/dev/null; then
        wget -q --show-progress -O "$NUCLEI_ZIP" "$NUCLEI_URL" || {
            echo "  [WARN] 下载失败，请手动下载放到 $NUCLEI_DIR/nuclei"
        }
    elif command -v curl &>/dev/null; then
        curl -L -o "$NUCLEI_ZIP" "$NUCLEI_URL" || {
            echo "  [WARN] 下载失败，请手动下载放到 $NUCLEI_DIR/nuclei"
        }
    else
        echo "  [WARN] 未找到 wget/curl，请手动下载 nuclei 放到 $NUCLEI_DIR/nuclei"
    fi

    if [ -f "$NUCLEI_ZIP" ]; then
        unzip -q -o "$NUCLEI_ZIP" -d "$NUCLEI_DIR/" 2>/dev/null || true
        # nuclei zip 解压后一般在当前目录，需要找到 binary
        BINARY=$(find "$NUCLEI_DIR" -name "nuclei" -type f 2>/dev/null | head -1)
        if [ -n "$BINARY" ] && [ "$BINARY" != "$NUCLEI_DIR/nuclei" ]; then
            mv "$BINARY" "$NUCLEI_DIR/nuclei"
        fi
        rm -f "$NUCLEI_ZIP"
        rm -f "$NUCLEI_DIR/LICENSE*" "$NUCLEI_DIR/README*" 2>/dev/null || true
        chmod +x "$NUCLEI_DIR/nuclei" 2>/dev/null || true
    fi
fi

# ---------- 3. 下载 Nuclei Templates ----------
echo "[3/3] 下载 Nuclei 官方模板库..."
if [ -d "$TEMPLATES_DIR/.git" ]; then
    echo "  模板库已存在，尝试更新..."
    cd "$TEMPLATES_DIR" && git pull --depth=1 2>/dev/null || echo "  [WARN] 更新失败，将使用现有模板"
else
    rm -rf "$TEMPLATES_DIR"
    echo "  git clone https://github.com/projectdiscovery/nuclei-templates.git ..."
    git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git "$TEMPLATES_DIR" 2>/dev/null || {
        echo "  [WARN] 模板下载失败，扫描时将仅使用自定义插件"
    }
fi

echo ""
echo "========================================="
echo " 工具准备完成！"
echo " nmap:          $NMAP_DIR/nmap"
echo " nuclei:        $NUCLEI_DIR/nuclei"
echo " templates:     $TEMPLATES_DIR"
echo "========================================="
