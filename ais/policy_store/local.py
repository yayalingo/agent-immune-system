"""策略存储（v1 本地）：把 rego 包与 manifest 落盘，记录每条规则的回归状态。"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

DEFAULT_STORE = Path.home() / ".ais" / "store"


def _store(store_dir: Optional[str]) -> Path:
    return Path(store_dir) if store_dir else DEFAULT_STORE


def _manifest_path(store: Path) -> Path:
    return store / "manifest.json"


def _load_manifest(store: Path) -> dict:
    p = _manifest_path(store)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"rules": {}}


def _save_manifest(store: Path, m: dict) -> None:
    store.mkdir(parents=True, exist_ok=True)
    _manifest_path(store).write_text(
        json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def deploy(rego_text: str, ir_list: list[dict], store_dir: Optional[str] = None,
           rego_test: Optional[str] = None) -> Path:
    store = _store(store_dir)
    (store / "policies").mkdir(parents=True, exist_ok=True)
    rego_path = store / "policies" / "ais_bundle.rego"
    rego_path.write_text(rego_text, encoding="utf-8")
    if rego_test:
        (store / "policies" / "ais_bundle_test.rego").write_text(rego_test, encoding="utf-8")
    m = _load_manifest(store)
    for ir in ir_list:
        sid = ir["meta"]["scenario_id"]
        m["rules"][sid] = {
            "asi_id": ir["meta"]["asi_id"],
            "rego_file": "ais_bundle.rego",
            "regression_passed": False,
            "deployed_at": time.time(),
        }
    _save_manifest(store, m)
    return rego_path


def mark_regression(scenario_id: str, passed: bool = True, store_dir: Optional[str] = None) -> None:
    store = _store(store_dir)
    m = _load_manifest(store)
    if scenario_id in m["rules"]:
        m["rules"][scenario_id]["regression_passed"] = passed
        _save_manifest(store, m)


def list_rules(store_dir: Optional[str] = None) -> dict:
    return _load_manifest(_store(store_dir)).get("rules", {})
