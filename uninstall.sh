#!/bin/bash

set -u

script_path="${BASH_SOURCE[0]}"
[[ "$script_path" == /* ]] || script_path="$PWD/$script_path"
repo_root=$(cd -P -- "${script_path%/*}" 2>/dev/null && pwd) || exit 3
exec /bin/bash "$repo_root/install.sh" uninstall "$@"
