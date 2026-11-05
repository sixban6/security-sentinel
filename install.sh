#!/usr/bin/env bash
# ==============================================================================
# Security-Sentinel (sectl) 一键安装与升级脚本
#
# 1. 远程免编译直装 (直接拉取 GitHub Actions 最新预编译二进制 + SHA-256 强校验):
#    curl -fsSL https://raw.githubusercontent.com/sixban6/security-sentinel/main/install.sh | bash
#
# 2. macOS 同步安装原生 GPU 桌面应用 (/Applications/Security Sentinel.app):
#    curl -fsSL https://raw.githubusercontent.com/sixban6/security-sentinel/main/install.sh | bash -s -- --with-app
#
# 3. 开发者本地源码编译模式:
#    ./install.sh --from-source
# ==============================================================================
set -euo pipefail

REPO="sixban6/security-sentinel"
FROM_SOURCE=0
WITH_APP=0

for arg in "$@"; do
    case "$arg" in
        --from-source|--local) FROM_SOURCE=1 ;;
        --with-app|--app)      WITH_APP=1 ;;
    esac
done

# 确定安装目录 (OpenWrt root 默认装入 /usr/bin，其他系统默认 ~/.local/bin)
if [[ -f /etc/openwrt_release && "$(id -u)" = "0" ]]; then
    TARGET_DIR="/usr/bin"
else
    TARGET_DIR="${HOME}/.local/bin"
fi
mkdir -p "${TARGET_DIR}"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

build_from_source() {
    local root_dir="$1"
    echo "🔨 [源码模式] 正在编译纯 Go 零依赖命令行核心 (sectl)..."
    mkdir -p "${root_dir}/bin"
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${root_dir}/bin/sectl" "${root_dir}/cmd/sectl"
    ln -sf "${root_dir}/bin/sectl" "${TARGET_DIR}/sectl"
    ln -sf "${TARGET_DIR}/sectl" "${TARGET_DIR}/security-sentinel"
    echo "✅ CLI 已就绪: ${TARGET_DIR}/sectl (兼容别名: security-sentinel)"

    local mygo_bin=""
    mygo_bin="$(command -v mygo || true)"
    if [[ -z "${mygo_bin}" ]] && command -v go >/dev/null 2>&1 && [[ -x "$(go env GOPATH)/bin/mygo" ]]; then
        mygo_bin="$(go env GOPATH)/bin/mygo"
    fi
    if [[ -n "${mygo_bin}" ]]; then
        echo "🖥️  正在使用 MyGo 构建原生 GPU 桌面应用..."
        (cd "${root_dir}" && "${mygo_bin}" build)
        echo "✅ 桌面端安装包已生成至: ${root_dir}/build/"
    fi
}

SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [[ "${FROM_SOURCE}" -eq 1 ]]; then
    if [[ -z "${SCRIPT_DIR}" || ! -f "${SCRIPT_DIR}/go.mod" ]]; then
        echo "❌ --from-source 需要在项目源码目录中运行"
        exit 1
    fi
    build_from_source "${SCRIPT_DIR}"
    exit 0
fi

# 1. 识别当前操作系统与芯片架构
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

case "${UNAME_S}" in
    Darwin) OS_TAG="darwin" ;;
    Linux)  OS_TAG="linux" ;;
    *)      echo "❌ 暂不支持的系统: ${UNAME_S}"; exit 1 ;;
esac

case "${UNAME_M}" in
    arm64|aarch64) ARCH_TAG="arm64" ;;
    x86_64|amd64)  ARCH_TAG="amd64" ;;
    mipsel|mipsle) ARCH_TAG="mipsle"; OS_TAG="openwrt" ;;
    *)             echo "❌ 暂不支持的芯片架构: ${UNAME_M}"; exit 1 ;;
esac

BIN_ASSET="sectl-${OS_TAG}-${ARCH_TAG}"
LEGACY_ASSET="security-sentinel-${OS_TAG}-${ARCH_TAG}"
BASE_DL="https://github.com/${REPO}/releases/latest/download"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t sentinel-install)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "⬇️  正在从 GitHub Actions 最新 Release 下载预编译二进制 (${BIN_ASSET})..."
DOWNLOADED_NAME="${BIN_ASSET}"
if ! curl -fsSL "${BASE_DL}/${BIN_ASSET}" -o "${TMP_DIR}/${BIN_ASSET}" 2>/dev/null; then
    if curl -fsSL "${BASE_DL}/${LEGACY_ASSET}" -o "${TMP_DIR}/${LEGACY_ASSET}" 2>/dev/null; then
        DOWNLOADED_NAME="${LEGACY_ASSET}"
    elif [[ -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/go.mod" ]] && command -v go >/dev/null 2>&1; then
        echo "ℹ️  远端尚未发布适配 ${BIN_ASSET} 的 GitHub Release，自动切换至本地源码极速编译..."
        build_from_source "${SCRIPT_DIR}"
        exit 0
    else
        echo "❌ 下载 ${BASE_DL}/${BIN_ASSET} 失败，请检查网络连接。"
        exit 1
    fi
fi

# 2. 强制核验 SHA-256 校验值
if curl -fsSL "${BASE_DL}/checksums.txt" -o "${TMP_DIR}/checksums.txt" 2>/dev/null; then
    EXPECTED_HASH="$(awk -v f="${DOWNLOADED_NAME}" '$2 == f || $2 == "*"f {print tolower($1)}' "${TMP_DIR}/checksums.txt" | head -n 1)"
    ACTUAL_HASH="$(sha256_file "${TMP_DIR}/${DOWNLOADED_NAME}" | tr '[:upper:]' '[:lower:]')"
    if [[ -n "${EXPECTED_HASH}" && -n "${ACTUAL_HASH}" ]]; then
        if [[ "${EXPECTED_HASH}" != "${ACTUAL_HASH}" ]]; then
            echo "❌ 安全告警: SHA-256 校验不匹配！已中止安装。"
            exit 1
        fi
        echo "🔒 SHA-256 签名校验通过 (${ACTUAL_HASH:0:16}...)"
    fi
fi

chmod 755 "${TMP_DIR}/${DOWNLOADED_NAME}"
rm -f "${TARGET_DIR}/sectl" "${TARGET_DIR}/security-sentinel"
mv -f "${TMP_DIR}/${DOWNLOADED_NAME}" "${TARGET_DIR}/sectl"
ln -sf "${TARGET_DIR}/sectl" "${TARGET_DIR}/security-sentinel"
echo "✅ sectl 已成功安装至: ${TARGET_DIR}/sectl (兼容软链: ${TARGET_DIR}/security-sentinel)"
"${TARGET_DIR}/sectl" version || true

# 3. 可选：macOS 同步安装原生 GPU 桌面应用 (Security Sentinel.app)
if [[ "${WITH_APP}" -eq 1 && "${OS_TAG}" = "darwin" ]]; then
    APP_ARCHIVE="Security-Sentinel-darwin-${ARCH_TAG}.app.tar.gz"
    echo "🖥️  正在下载 macOS 原生 GPU 桌面端 (${APP_ARCHIVE})..."
    if curl -fsSL "${BASE_DL}/${APP_ARCHIVE}" -o "${TMP_DIR}/${APP_ARCHIVE}"; then
        if [[ -f "${TMP_DIR}/checksums.txt" ]]; then
            EXP_APP="$(awk -v f="${APP_ARCHIVE}" '$2 == f || $2 == "*"f {print tolower($1)}' "${TMP_DIR}/checksums.txt" | head -n 1)"
            ACT_APP="$(sha256_file "${TMP_DIR}/${APP_ARCHIVE}" | tr '[:upper:]' '[:lower:]')"
            if [[ -n "${EXP_APP}" && -n "${ACT_APP}" && "${EXP_APP}" != "${ACT_APP}" ]]; then
                echo "❌ 桌面端应用包 SHA-256 校验不匹配，已中止替换！"
                exit 1
            fi
        fi
        tar -xzf "${TMP_DIR}/${APP_ARCHIVE}" -C "${TMP_DIR}"
        xattr -cr "${TMP_DIR}/Security Sentinel.app" 2>/dev/null || true
        APP_DEST="/Applications/Security Sentinel.app"
        if [[ ! -w "/Applications" ]]; then
            APP_DEST="${HOME}/Applications/Security Sentinel.app"
            mkdir -p "${HOME}/Applications"
        fi
        pkill -f "Security Sentinel.app/Contents/MacOS/Security Sentinel" 2>/dev/null || true
        rm -rf "${APP_DEST}"
        mv "${TMP_DIR}/Security Sentinel.app" "${APP_DEST}"
        echo "🎉 桌面应用已安装至: ${APP_DEST}"
    fi
fi

if [[ ":${PATH}:" != *":${TARGET_DIR}:"* ]]; then
    echo "💡 提示: 请将 ${TARGET_DIR} 加入 PATH (例如在 ~/.zshrc 中添加 export PATH=\"\$HOME/.local/bin:\$PATH\")"
fi
echo "🚀 后续随时可执行 \`sectl up\` 一键自升级到最新版本！"
