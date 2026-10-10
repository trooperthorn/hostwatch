"""A stand-in for the docker, pip, python and systemd-run programs that agent.update runs.

The tests put a small wrapper on disk that runs this file with the real interpreter, and point the
executor's program paths at the wrappers, so the real `subprocess_runner` (an argument list, no shell,
a timeout) is what gets exercised. The state file named by HOSTWATCH_FAKE_STATE holds a scenario, the
containers and images the fake daemon knows, and a log of every call. The fake keeps enough of the
`docker inspect` shape for the executor to rebuild the run command, and it moves containers between
names the way docker does, so a rollback can be checked from the final state.

Scenario keys:
  pull: "changed" (the image id becomes `pulled_id`), "unchanged", "fail" or "hang" (sleep past the timeout)
  run: "ok", "fail" (docker run exits 125) or "exits" (the container is created but not running)
  pip: "ok" or "fail"
  pip_version: what the venv python prints after the install
"""

from __future__ import annotations

import json
import os
import sys
import time


def _load():
    path = os.environ["HOSTWATCH_FAKE_STATE"]
    with open(path, encoding="utf-8") as fh:
        return path, json.load(fh)


def _save(path, state):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def _fail(path, state, text, code=1):
    _save(path, state)
    sys.stderr.write(text + "\n")
    return code


def docker(args, path, state):
    scenario = state.get("scenario", {})
    containers = state.setdefault("containers", {})
    images = state.setdefault("images", {})
    if args[:3] == ["inspect", "--type", "container"]:
        name = args[3]
        if name not in containers:
            return _fail(path, state, f"Error: No such container: {name}")
        print(json.dumps([containers[name]]))
        return 0
    if args[:2] == ["image", "inspect"]:
        ref = args[2]
        if ref not in images:
            return _fail(path, state, f"Error: No such image: {ref}")
        print(json.dumps([images[ref]]))
        return 0
    if args[0] == "pull":
        ref = args[1]
        mode = scenario.get("pull", "unchanged")
        if mode == "hang":
            time.sleep(float(scenario.get("hang_s", 5)))
            return 0
        if mode == "fail":
            return _fail(path, state, f"Error response from daemon: manifest for {ref} not found")
        if mode == "changed":
            image = images.setdefault(ref, {"Config": {"Labels": {}}})
            image["Id"] = scenario["pulled_id"]
            image["Config"]["Labels"] = dict(scenario.get("pulled_labels", {}))
            print(f"Status: Downloaded newer image for {ref}")
        else:
            print(f"Status: Image is up to date for {ref}")
        _save(path, state)
        return 0
    if args[0] == "stop":
        name = args[1]
        if name not in containers:
            return _fail(path, state, f"Error: No such container: {name}")
        containers[name]["State"]["Running"] = False
        _save(path, state)
        return 0
    if args[0] == "start":
        name = args[1]
        if name not in containers:
            return _fail(path, state, f"Error: No such container: {name}")
        if scenario.get("start_prev") == "fail" and containers[name].get("_was_prev"):
            return _fail(path, state, "Error response from daemon: cannot start")
        containers[name]["State"]["Running"] = True
        _save(path, state)
        return 0
    if args[0] == "rename":
        old, new = args[1], args[2]
        if old not in containers:
            return _fail(path, state, f"Error: No such container: {old}")
        if new in containers:
            return _fail(path, state, f"Error response from daemon: Conflict. The container name /{new} is already in use")
        record = containers.pop(old)
        record["Name"] = "/" + new
        if new.endswith("-prev"):
            record["_was_prev"] = True
        containers[new] = record
        _save(path, state)
        return 0
    if args[:2] == ["rm", "-f"]:
        name = args[2]
        if name not in containers:
            return _fail(path, state, f"Error: No such container: {name}")
        del containers[name]
        _save(path, state)
        return 0
    if args[0] == "run":
        mode = scenario.get("run", "ok")
        if mode == "fail":
            return _fail(path, state, "docker: Error response from daemon: failed to create task", 125)
        name = args[args.index("--name") + 1]
        if name in containers:
            return _fail(path, state, f"docker: Error response from daemon: Conflict. The container name /{name} is already in use", 125)
        ref = args[-1]
        image = images.get(ref, {"Id": "sha256:" + "0" * 64, "Config": {"Labels": {}}})
        containers[name] = {"Id": "c" * 64, "Name": "/" + name, "Image": image["Id"],
                            "Config": {"Image": ref, "Labels": dict(image.get("Config", {}).get("Labels", {})),
                                       "Env": [], "User": ""},
                            "HostConfig": {}, "Mounts": [], "State": {"Running": mode != "exits"},
                            "_run_args": args}
        print("c" * 64)
        _save(path, state)
        return 0
    return _fail(path, state, f"fake docker: unsupported arguments {args!r}", 2)


def pip(args, path, state):
    mode = state.get("scenario", {}).get("pip", "ok")
    if mode == "fail":
        return _fail(path, state, "ERROR: Could not install packages due to an OSError", 1)
    state["pip_installed"] = True
    _save(path, state)
    return 0


def python(args, path, state):
    if args == ["-m", "hostwatch.control.installed"]:
        print(state.get("scenario", {}).get("pip_version", ""))
        return 0
    return _fail(path, state, f"fake python: unsupported arguments {args!r}", 2)


def systemd_run(args, path, state):
    state["restart_scheduled"] = args
    _save(path, state)
    print("Running timer as unit: run-r1.timer")
    return 0


PROGRAMS = {"docker": docker, "pip": pip, "python": python, "systemd-run": systemd_run}


def main(argv):
    program, args = argv[1], argv[2:]
    path, state = _load()
    state.setdefault("calls", []).append([program] + args)
    _save(path, state)
    return PROGRAMS[program](args, path, state)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
