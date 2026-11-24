#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
PYTHON_BIN=${PYTHON_BIN:-python3}
for cmd in "$PYTHON_BIN" node npm; do
  command -v "$cmd" >/dev/null || { echo "Не найдена команда: $cmd" >&2; exit 1; }
done
"$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else "Требуется Python 3.10 или новее")'
node -e 'if (+process.versions.node.split(".")[0]<22) {console.error("Требуется Node.js 22 или новее");process.exit(1)}'
if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON_BIN" -m venv .venv
fi
.venv/bin/python -m pip install -r requirements.txt
if [[ -f package-lock.json ]]; then
  npm ci --omit=dev --no-fund
else
  npm install --omit=dev --no-fund
fi
.venv/bin/python -c 'import sys; sys.path.insert(0,"server"); import aiohttp, yarl, opaque_adapter; opaque_adapter.check()'
# Real local OPAQUE handshake through the same worker used in production.
node tools/check-opaque.mjs
printf '\nЗависимости установлены. Конфигурация не изменена.\n'
printf 'Первый запуск: .venv/bin/python server.py\n'
printf 'Настройка отдельно: .venv/bin/python server.py configure\n'
