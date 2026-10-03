"""The read-only TrueNAS client against a fake JSON-RPC server bound to 127.0.0.1."""
import asyncio
import json
import logging

import pytest
from websockets.asyncio.server import serve

from hostwatch.config import Config
from hostwatch.truenas.client import (ALLOWED_METHODS, MethodNotAllowed, TruenasClient, convert_dates)

GOOD_KEY = "1-goodkeygoodkeygoodkey"
POOLS = [{"name": "Vault", "status": "ONLINE", "scan": {"start_time": {"$date": 1_700_000_000_500}}}]


class FakeServer:
    def __init__(self, answers=None, hang=False):
        self.frames = []
        self.answers = answers or {"pool.query": POOLS}
        self.hang = hang

    async def handler(self, ws):
        async for raw in ws:
            frame = json.loads(raw)
            self.frames.append(frame)
            if self.hang:
                await ws.wait_closed()
            if frame["method"] == "auth.login_with_api_key":
                result = frame["params"] == [GOOD_KEY]
            else:
                result = self.answers.get(frame["method"])
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": frame["id"], "result": result}))


def _run(server, body):
    async def main():
        async with serve(server.handler, "127.0.0.1", 0) as srv:
            port = srv.sockets[0].getsockname()[1]
            return await body(f"ws://127.0.0.1:{port}/api/current")
    return asyncio.run(main())


def _key_file(tmp_path, text=GOOD_KEY):
    path = tmp_path / "key"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_login_and_pool_query_convert_dates(tmp_path):
    server = FakeServer()

    async def body(url):
        client = TruenasClient(url, _key_file(tmp_path), timeout=5)
        try:
            return await client.call("pool.query")
        finally:
            await client.close()

    result = _run(server, body)
    assert result.available
    assert result.value[0]["scan"]["start_time"] == 1_700_000_000.5
    assert [f["method"] for f in server.frames] == ["auth.login_with_api_key", "pool.query"]


@pytest.mark.parametrize("method", ["pool.scrub.run", "disk.wipe", "pool.query; x", ""])
def test_non_allowlisted_method_raises_before_any_frame(tmp_path, method):
    server = FakeServer()

    async def body(url):
        client = TruenasClient(url, _key_file(tmp_path), timeout=5)
        try:
            with pytest.raises(MethodNotAllowed):
                await client.call(method)
        finally:
            await client.close()

    _run(server, body)
    assert server.frames == []


def test_send_path_itself_refuses_other_methods(tmp_path):
    async def body(url):
        client = TruenasClient(url, _key_file(tmp_path), timeout=5)
        with pytest.raises(MethodNotAllowed):
            await client._send({"jsonrpc": "2.0", "id": 1, "method": "disk.wipe", "params": []})

    server = FakeServer()
    _run(server, body)
    assert server.frames == []


def test_allowlist_is_exactly_the_query_methods():
    assert ALLOWED_METHODS == {"auth.login_with_api_key", "system.info", "system.boot_id", "pool.query",
                               "disk.query", "disk.temperatures", "alert.list", "pool.scrub.query"}


def test_bad_key_is_unavailable_and_sends_no_query(tmp_path):
    server = FakeServer()

    async def body(url):
        client = TruenasClient(url, _key_file(tmp_path, "wrong-key"), timeout=5)
        return await client.call("pool.query")

    result = _run(server, body)
    assert not result.available and "rejected" in result.reason
    assert "wrong-key" not in result.reason
    assert [f["method"] for f in server.frames] == ["auth.login_with_api_key"]


def test_timeout_is_unavailable(tmp_path):
    server = FakeServer(hang=True)

    async def body(url):
        client = TruenasClient(url, _key_file(tmp_path), timeout=0.3)
        try:
            return await client.call("pool.query")
        finally:
            await client.close()

    result = _run(server, body)
    assert not result.available and result.reason == "timed out"


def test_connection_refused_is_unavailable(tmp_path):
    async def main():
        client = TruenasClient("ws://127.0.0.1:1/api/current", _key_file(tmp_path), timeout=5)
        return await client.call("pool.query")

    result = asyncio.run(main())
    assert not result.available and result.reason.startswith("connection failed")


def test_missing_key_file_and_plain_ws_to_remote_host(tmp_path):
    async def main():
        a = await TruenasClient("ws://127.0.0.1:1/x", str(tmp_path / "none")).call("system.info")
        b = await TruenasClient("ws://nas.example.test/x", _key_file(tmp_path)).call("system.info")
        c = await TruenasClient("http://nas/x", _key_file(tmp_path)).call("system.info")
        return a, b, c

    a, b, c = asyncio.run(main())
    assert not a.available and "unreadable" in a.reason
    assert not b.available and "wss" in b.reason
    assert not c.available


def test_reconnects_after_the_server_drops_the_connection(tmp_path):
    server = FakeServer()

    async def body(url):
        client = TruenasClient(url, _key_file(tmp_path), timeout=5)
        try:
            first = await client.call("system.info")
            await client._ws.close()
            second = await client.call("pool.query")
            return first, second
        finally:
            await client.close()

    first, second = _run(server, body)
    assert first.available and second.available
    assert [f["method"] for f in server.frames].count("auth.login_with_api_key") == 2


def test_key_never_appears_in_logs_or_reprs(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    server = FakeServer()

    async def body(url):
        client = TruenasClient(url, _key_file(tmp_path), timeout=5)
        try:
            await client.call("pool.query")
            return repr(client) + str(vars(client)["_key"].__repr__())
        finally:
            await client.close()

    text = _run(server, body)
    assert GOOD_KEY not in text
    assert GOOD_KEY not in caplog.text


def test_tls_defaults_verify_and_insecure_is_explicit(tmp_path):
    ctx = TruenasClient("wss://nas/x", "k")._ssl_context("wss", "nas")
    assert ctx.verify_mode.name == "CERT_REQUIRED" and ctx.check_hostname
    ctx = TruenasClient("wss://nas/x", "k", insecure=True)._ssl_context("wss", "nas")
    assert ctx.verify_mode.name == "CERT_NONE"


def test_convert_dates_nested_and_untouched_values():
    data = {"a": {"$date": 1500}, "b": [{"c": {"$date": 2000}}, "x", 3, True], "d": {"$date": "no"}}
    assert convert_dates(data) == {"a": 1.5, "b": [{"c": 2.0}, "x", 3, True], "d": {"$date": "no"}}


def test_from_config(monkeypatch):
    monkeypatch.delenv("HOSTWATCH_TRUENAS_URL", raising=False)
    assert TruenasClient.from_config(Config()) is None
    monkeypatch.setenv("HOSTWATCH_TRUENAS_URL", "wss://nas/api/current")
    monkeypatch.setenv("HOSTWATCH_TRUENAS_API_KEY_FILE", "/run/secrets/key")
    assert TruenasClient.from_config(Config()) is not None


def test_environment_proxy_is_ignored_and_the_client_connects_directly(tmp_path, monkeypatch):
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    server = FakeServer()

    async def body(url):
        client = TruenasClient(url, _key_file(tmp_path), timeout=5)
        try:
            return await client.call("pool.query")
        finally:
            await client.close()

    result = _run(server, body)
    assert result.available
    assert server.frames[0]["method"] == "auth.login_with_api_key"
