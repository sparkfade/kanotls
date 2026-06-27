#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Constants
# ============================================================
GITHUB_REPO="sparkfade/kanotls"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
GITHUB_DOWNLOAD="https://github.com/${GITHUB_REPO}/releases/download"
GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_REPO}"

BIN_DEST="/usr/local/bin/kanotls"
CONFIG_DIR="/etc/kanotls"
CONFIG_DEST="${CONFIG_DIR}/config.json"
SERVICE_DEST="/etc/systemd/system/kanotls.service"
EXAMPLE_PATH="deploy/linux/config.json.example"
SERVICE_PATH="deploy/linux/kanotls.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================
# Helpers
# ============================================================
die() {
    echo -e "${RED}ERROR:${NC} $*" >&2
    exit 1
}

info() { echo -e "${GREEN}==>${NC} $*"; }
warn() { echo -e "${YELLOW}WARN:${NC} $*" >&2; }

# Bilingual message: _msg "中文" "English"
_msg() {
    if [ "${MENU_LANG:-}" = "zh" ]; then echo -e "$1"; else echo -e "$2"; fi
}

download() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$dest"
    else
        die "neither curl nor wget found; please install one of them"
    fi
}

# ============================================================
# Pre-flight checks
# ============================================================
if [ "$(id -u)" -ne 0 ]; then
    die "this script must be run as root (use sudo)"
fi

OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    die "unsupported operating system: $OS (only Linux is supported)"
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   ARTIFACT="kanotls-linux-64" ;;
    i686|i386)      ARTIFACT="kanotls-linux-32" ;;
    aarch64|arm64)  ARTIFACT="kanotls-linux-arm64-v8a" ;;
    armv7l)         ARTIFACT="kanotls-linux-arm32-v7a" ;;
    *)              die "unsupported architecture: $ARCH" ;;
esac

# ============================================================
# Language selection
# ============================================================
select_language() {
    echo ""
    echo "========================================"
    echo "  Select Language / 选择语言"
    echo "========================================"
    echo "  1) 中文"
    echo "  2) English"
    echo "========================================"
    echo ""
    while true; do
        read -rp "  > " choice < /dev/tty
        case "$choice" in
            1) MENU_LANG="zh"; break ;;
            2) MENU_LANG="en"; break ;;
            *) echo -e "  ${YELLOW}$(_msg "无效选择" "Invalid choice")${NC}" ;;
        esac
    done
    echo ""
}

# ============================================================
# Fetch release tag
# ============================================================
fetch_tag() {
    local mode="$1"
    local api_url
    if [ "$mode" = "prerelease" ]; then
        api_url="${GITHUB_API}/releases"
    else
        api_url="${GITHUB_API}/releases/latest"
    fi

    TAG=$(download "$api_url" - 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/')
    if [ -z "$TAG" ]; then
        warn "$(_msg "获取版本号失败" "failed to fetch release tag")"
        return 1
    fi
    info "$(_msg "版本: " "release: ")${TAG}"
    return 0
}

# ============================================================
# Pre-release sub-menu
# ============================================================
ask_prerelease() {
    echo ""
    _msg \
        "  选择版本类型:" \
        "  Select release type:"
    _msg \
        "    1) 稳定版 (Stable)" \
        "    1) Stable"
    _msg \
        "    2) 预发布版 (Pre-release)" \
        "    2) Pre-release"
    _msg \
        "    0) 返回" \
        "    0) Back"
    echo ""
    while true; do
        read -rp "  > " choice < /dev/tty
        case "$choice" in
            1) RELEASE_TYPE="stable"; return 0 ;;
            2) RELEASE_TYPE="prerelease"; return 0 ;;
            0) return 1 ;;
            *) _msg "  无效选择，请重试。" "  Invalid choice, please retry." ;;
        esac
    done
}

# ============================================================
# Core: download & install files
# ============================================================
install_files() {
    local tag="$1"
    local tmp_bin tmp_example tmp_service

    # --- binary ---
    local binary_url="${GITHUB_DOWNLOAD}/${tag}/${ARTIFACT}"
    tmp_bin="$(mktemp)"
    info "$(_msg "下载 ${ARTIFACT}..." "downloading ${ARTIFACT}...")"
    if ! download "$binary_url" "$tmp_bin"; then
        rm -f "$tmp_bin"
        return 1
    fi
    chmod 755 "$tmp_bin"
    info "$(_msg "安装二进制到 ${BIN_DEST}..." "installing binary to ${BIN_DEST}...")"
    mv "$tmp_bin" "$BIN_DEST"

    # --- config skeleton ---
    local example_url="${GITHUB_RAW}/${tag}/${EXAMPLE_PATH}"
    tmp_example="$(mktemp)"
    info "$(_msg "下载配置模板..." "downloading config skeleton...")"
    if ! download "$example_url" "$tmp_example"; then
        rm -f "$tmp_example"
        return 1
    fi
    mkdir -p "$CONFIG_DIR"
    cp -f "$tmp_example" "${CONFIG_DIR}/config.json.example"
    rm -f "$tmp_example"

    if [ ! -f "$CONFIG_DEST" ]; then
        info "$(_msg "未找到现有 config.json，复制模板..." "no existing config.json found, copying skeleton...")"
        cp "${CONFIG_DIR}/config.json.example" "$CONFIG_DEST"
    else
        info "$(_msg "保留现有 config.json（未覆盖）" "existing config.json preserved (not overwritten)")"
    fi

    # --- systemd unit ---
    local service_url="${GITHUB_RAW}/${tag}/${SERVICE_PATH}"
    tmp_service="$(mktemp)"
    info "$(_msg "下载 systemd 单元..." "downloading systemd unit...")"
    if ! download "$service_url" "$tmp_service"; then
        rm -f "$tmp_service"
        return 1
    fi
    cp -f "$tmp_service" "$SERVICE_DEST"
    rm -f "$tmp_service"

    systemctl daemon-reload
    return 0
}

# ============================================================
# Action: Install
# ============================================================
do_install() {
    if [ -f "$BIN_DEST" ]; then
        warn "$(_msg "kanotls 已安装，请使用更新功能。" "kanotls is already installed, use update instead.")"
        return 1
    fi

    if ! ask_prerelease; then return 0; fi
    if ! fetch_tag "$RELEASE_TYPE"; then return 1; fi
    if ! install_files "$TAG"; then return 1; fi

    echo ""
    echo -e "${BOLD}$(_msg "=== 安装完成 ===" "=== Installation complete ===")${NC}"
    echo ""
    _msg \
        "${YELLOW}重要:${NC} 启动服务前请编辑配置文件:" \
        "${YELLOW}IMPORTANT:${NC} Edit the configuration before starting the service:"
    _msg \
        "  ${BOLD}1.${NC} 编辑 ${CONFIG_DEST}" \
        "  ${BOLD}1.${NC} Edit ${CONFIG_DEST}"
    _msg \
        "     - 将占位密码替换为安全密码:" \
        "     - Replace the placeholder password with a secure one:"
    echo  "       ${BOLD}openssl rand -base64 48${NC}"
    _msg \
        "     - 设置 camouflage.host 和 camouflage.port" \
        "     - Set camouflage.host and camouflage.port to your reference endpoint"
    _msg \
        "  ${BOLD}2.${NC} 启用并启动服务:" \
        "  ${BOLD}2.${NC} Enable and start the service:"
    echo  "       ${BOLD}systemctl enable --now kanotls${NC}"
    _msg \
        "  ${BOLD}3.${NC} 查看状态:" \
        "  ${BOLD}3.${NC} Check status:"
    echo  "       ${BOLD}systemctl status kanotls${NC}"
    _msg \
        "  ${BOLD}4.${NC} 查看日志:" \
        "  ${BOLD}4.${NC} View logs:"
    echo  "       ${BOLD}journalctl -u kanotls -f${NC}"
    echo ""
    return 0
}

# ============================================================
# Action: Update
# ============================================================
do_update() {
    if [ ! -f "$BIN_DEST" ]; then
        warn "$(_msg "kanotls 未安装，请先安装。" "kanotls is not installed, use install first.")"
        return 1
    fi

    if ! ask_prerelease; then return 0; fi
    if ! fetch_tag "$RELEASE_TYPE"; then return 1; fi
    if ! install_files "$TAG"; then return 1; fi

    if systemctl is-active --quiet kanotls 2>/dev/null; then
        info "$(_msg "重启 kanotls 服务..." "restarting kanotls service...")"
        systemctl restart kanotls
    else
        _msg \
            "${YELLOW}提示:${NC} 服务未运行，可手动启动: systemctl enable --now kanotls" \
            "${YELLOW}Hint:${NC} service not running, start it with: systemctl enable --now kanotls"
    fi

    echo ""
    echo -e "${BOLD}$(_msg "=== 更新完成 ===" "=== Update complete ===")${NC}"
    echo ""
    return 0
}

# ============================================================
# Action: Uninstall
# ============================================================
do_uninstall() {
    echo ""
    _msg \
        "  确认卸载 kanotls？此操作不可撤销。" \
        "  Confirm uninstall kanotls? This cannot be undone."
    _msg \
        "    1) 确认卸载 (Confirm)" \
        "    1) Confirm"
    _msg \
        "    0) 取消 (Cancel)" \
        "    0) Cancel"
    echo ""
    read -rp "  > " confirm < /dev/tty
    case "$confirm" in
        1) ;;
        *) return 0 ;;
    esac

    info "$(_msg "停止并禁用 kanotls 服务..." "stopping and disabling kanotls service...")"
    systemctl stop kanotls 2>/dev/null || true
    systemctl disable kanotls 2>/dev/null || true

    if [ -f "$SERVICE_DEST" ]; then
        rm -f "$SERVICE_DEST"
        systemctl daemon-reload
    fi

    if [ -f "$BIN_DEST" ]; then
        info "$(_msg "删除 ${BIN_DEST}..." "removing ${BIN_DEST}...")"
        rm -f "$BIN_DEST"
    fi

    if [ -d "$CONFIG_DIR" ]; then
        info "$(_msg "删除 ${CONFIG_DIR}..." "removing ${CONFIG_DIR}...")"
        rm -rf "$CONFIG_DIR"
    fi

    echo ""
    echo -e "${BOLD}$(_msg "=== 卸载完成 ===" "=== Uninstall complete ===")${NC}"
    echo ""
    return 0
}

# ============================================================
# Main menu
# ============================================================
main_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo "          Kanotls Installer"
        echo "========================================"
        _msg \
            "  1) 安装 (Install)" \
            "  1) Install"
        _msg \
            "  2) 更新 (Update)" \
            "  2) Update"
        _msg \
            "  3) 卸载 (Uninstall)" \
            "  3) Uninstall"
        _msg \
            "  0) 退出 (Exit)" \
            "  0) Exit"
        echo "========================================"
        echo ""
        read -rp "  > " choice < /dev/tty

        case "$choice" in
            1) set +e; do_install; set -e ;; 
            2) set +e; do_update; set -e ;;
            3) set +e; do_uninstall; set -e ;;
            0) exit 0 ;;
            *) _msg "  无效选择，请重试。" "  Invalid choice, please retry." ;;
        esac
    done
}

# ============================================================
# Entry point
# ============================================================
select_language
main_menu
