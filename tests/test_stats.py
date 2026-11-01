import pytest
from fastapi import HTTPException

STAT_CSV = (
    "# pxname,svname,qcur,qmax,scur,smax,status,weight,type,check_status,\n"
    "http_in,FRONTEND,,,3,10,OPEN,,0,,\n"
    "app_backend,app1,0,0,1,4,UP,1,2,L7OK,\n"
    "app_backend,app2,0,0,0,2,no check,1,2,,\n"
    "app_backend,BACKEND,0,0,1,4,UP,2,1,,\n"
    "http_in,sock-1,,,0,1,OPEN,,3,,\n"
    "\n"
)


def _node(env):
    return env["db"].one("SELECT * FROM nodes ORDER BY id LIMIT 1")


def test_show_stat_maps_numeric_haproxy_types(env, monkeypatch):
    from app.services import runtime

    monkeypatch.setattr(runtime, "runtime_cmd", lambda node, cmd: STAT_CSV)
    rows = runtime.show_stat(_node(env))

    assert [(r["svname"], r["type"], r["type_name"]) for r in rows] == [
        ("FRONTEND", "0", "frontend"),
        ("app1", "2", "server"),
        ("app2", "2", "server"),
        ("BACKEND", "1", "backend"),
        ("sock-1", "3", "listener"),
    ]
    assert rows[1]["pxname"] == "app_backend"
    assert rows[1]["check_status"] == "L7OK"


def test_show_stat_rejects_non_csv_socket_answer(env, monkeypatch):
    from app.services import runtime

    monkeypatch.setattr(runtime, "runtime_cmd", lambda node, cmd: "Permission denied\n\n")
    with pytest.raises(runtime.RuntimeResponseError):
        runtime.show_stat(_node(env))


def test_node_stat_reports_unexpected_socket_answer(env, monkeypatch):
    from app.routers import stats
    from app.services import runtime

    monkeypatch.setattr(runtime, "runtime_cmd", lambda node, cmd: "Unknown command\n")
    res = stats.node_stat(_node(env)["id"])

    assert res == {
        "ok": False,
        "error": "Runtime-Socket lieferte keine Statistikdaten",
        "rows": [],
    }


def test_node_stat_returns_rows_with_type_name(env, monkeypatch):
    from app.routers import stats
    from app.services import runtime

    monkeypatch.setattr(runtime, "runtime_cmd", lambda node, cmd: STAT_CSV)
    res = stats.node_stat(_node(env)["id"])

    assert res["ok"] is True
    assert {r["type_name"] for r in res["rows"]} == {"frontend", "backend", "server", "listener"}


def test_set_server_state_accepts_empty_haproxy_answer(env, monkeypatch):
    from app.services import runtime

    calls = []

    def fake_cmd(node, cmd):
        calls.append(cmd)
        return "\n"

    monkeypatch.setattr(runtime, "runtime_cmd", fake_cmd)
    assert runtime.set_server_state(_node(env), "app_backend", "app1", "drain") == "\n"
    assert calls == ["set server app_backend/app1 state drain"]


def test_server_state_reports_runtime_error_instead_of_success(env, monkeypatch):
    from app.routers import stats
    from app.services import runtime

    nid = _node(env)["id"]
    body = stats.ServerStateIn(backend="app_backend", server="app1", state="maint")

    monkeypatch.setattr(runtime, "runtime_cmd", lambda node, cmd: "Permission denied\n\n")
    with pytest.raises(HTTPException) as exc:
        stats.server_state(nid, body)
    assert exc.value.status_code == 502
    assert "level admin" in exc.value.detail

    monkeypatch.setattr(runtime, "runtime_cmd", lambda node, cmd: "No such backend.\n\n")
    with pytest.raises(HTTPException) as exc:
        stats.server_state(nid, body)
    assert exc.value.detail == "No such backend."
