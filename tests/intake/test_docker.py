"""Docker runner argument and failure-mapping tests (AT3/AT9).

Every test here uses a fake command runner. Nothing in this module may call
the real ``docker`` binary.
"""

import os
import sys

import pytest

from pry.intake.docker import (
    CommandResult,
    DockerRunner,
    SubprocessRunner,
    readiness_command,
)
from pry.intake.errors import (
    BUILD_FAILED,
    DOCKER_UNAVAILABLE,
    READY_TIMEOUT,
    SANDBOX_ERROR,
    START_FAILED,
    IntakeError,
)

DIGEST = "sha256:" + "a" * 64
FORBIDDEN = (
    "docker.sock",
    "--privileged",
    "--pid=host",
    "--ipc=host",
    "--uts=host",
    "--device",
)


class FakeRunner:
    """Records every argv and returns scripted results in order."""

    def __init__(self, results=None):
        self.calls = []
        self.results = list(results or [])

    def run(self, args, timeout):
        self.calls.append((list(args), timeout))
        if self.results:
            result = self.results.pop(0)
            return result(args) if callable(result) else result
        return CommandResult(0, b"", b"", False)


def _pair(argv, flag, value):
    assert (flag, value) in list(zip(argv, argv[1:]))


def _assert_security(argv, uid=501, gid=20):
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert "--read-only" in argv
    assert "--tmpfs=/tmp:rw,exec" in argv
    assert "--user=%d:%d" % (uid, gid) in argv
    assert "--memory=2g" in argv
    assert "--cpus=2" in argv
    assert "--pids-limit=512" in argv
    assert "--ulimit=nofile=4096" in argv
    _pair(argv, "-e", "HOME=/tmp")


def test_available_calls_docker_info():
    fake = FakeRunner([CommandResult(0, b"", b"", False)])

    assert DockerRunner(runner=fake).available() is True
    assert fake.calls[0][0] == ["docker", "info"]


def test_available_is_false_on_nonzero():
    fake = FakeRunner([CommandResult(1, b"", b"daemon down", False)])

    assert DockerRunner(runner=fake).available() is False


def test_available_is_false_on_timeout():
    fake = FakeRunner([CommandResult(-1, b"", b"", True)])

    assert DockerRunner(runner=fake).available() is False


def test_ensure_image_uses_a_cached_image_without_pulling():
    fake = FakeRunner([CommandResult(0, (DIGEST + "\n").encode())])

    digest = DockerRunner(runner=fake).ensure_image("node:22-bookworm-slim")

    assert digest == DIGEST
    assert len(fake.calls) == 1
    assert fake.calls[0][0][:3] == ["docker", "image", "inspect"]


def test_ensure_image_pulls_then_reads_the_repo_digest():
    fake = FakeRunner(
        [
            CommandResult(1, b"", b"no such image", False),
            CommandResult(0, b"", b"", False),
            CommandResult(0, (DIGEST + "\n").encode(), b"", False),
        ]
    )

    digest = DockerRunner(runner=fake).ensure_image("node:22-bookworm-slim")

    assert digest == DIGEST
    assert fake.calls[0][0][:3] == ["docker", "image", "inspect"]
    assert fake.calls[1][0] == ["docker", "pull", "node:22-bookworm-slim"]
    assert fake.calls[2][0] == [
        "docker",
        "image",
        "inspect",
        "--format",
        "{{index .RepoDigests 0}}",
        "node:22-bookworm-slim",
    ]


def test_ensure_image_failure_is_sandbox_error():
    fake = FakeRunner(
        [
            CommandResult(1, b"", b"no such image", False),
            CommandResult(1, b"", b"manifest unknown", False),
        ]
    )

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).ensure_image("node:22-bookworm-slim")

    assert exc.value.cause == SANDBOX_ERROR


def test_build_uses_bridge_network_and_security_flags(tmp_path):
    fake = FakeRunner([CommandResult(0, b"", b"", False)])
    workspace = tmp_path / "copy"

    result = DockerRunner(runner=fake, uid=501, gid=20).build(
        "node:22-bookworm-slim", workspace, ["npm", "ci"], timeout=600
    )

    argv, timeout = fake.calls[0]
    assert argv[:2] == ["docker", "run"]
    assert argv[2] == "--rm"
    assert "--network=bridge" in argv
    assert "--network=none" not in argv
    assert "--name" not in argv
    assert "-d" not in argv
    _assert_security(argv)
    _pair(argv, "-v", "%s:/app" % workspace)
    _pair(argv, "-w", "/app")
    assert argv[-3:] == ["node:22-bookworm-slim", "npm", "ci"]
    assert result.returncode == 0
    assert timeout == 600


def test_start_is_detached_on_no_network_without_port_publishing(tmp_path):
    fake = FakeRunner([CommandResult(0, b"container123\n", b"", False)])
    workspace = tmp_path / "copy"

    container = DockerRunner(runner=fake, uid=501, gid=20).start(
        "node:22-bookworm-slim",
        workspace,
        "pry-abc",
        ["npm", "run", "start"],
        3000,
    )

    assert container == "container123"
    argv, _ = fake.calls[0]
    assert argv[:2] == ["docker", "run"]
    assert "-d" in argv
    _pair(argv, "--name", "pry-abc")
    assert "--network=none" in argv
    assert "--network=bridge" not in argv
    assert "--rm" not in argv
    assert "-p" not in argv
    assert "-P" not in argv
    _assert_security(argv)
    _pair(argv, "-v", "%s:/app" % workspace)
    _pair(argv, "-w", "/app")
    _pair(argv, "-e", "PORT=3000")
    assert argv[-4:] == ["node:22-bookworm-slim", "npm", "run", "start"]


def test_limits_are_configurable(tmp_path):
    fake = FakeRunner([CommandResult(0, b"", b"", False)])

    DockerRunner(
        runner=fake, uid=501, gid=20, memory="1g", cpus="1", pids=64
    ).build("img", tmp_path, ["true"])

    argv, _ = fake.calls[0]
    assert "--memory=1g" in argv
    assert "--cpus=1" in argv
    assert "--pids-limit=64" in argv


def test_default_user_is_the_host_user(tmp_path):
    fake = FakeRunner([CommandResult(0, b"", b"", False)])
    uid = os.getuid() if hasattr(os, "getuid") else 0
    gid = os.getgid() if hasattr(os, "getgid") else 0

    DockerRunner(runner=fake).build("img", tmp_path, ["true"])

    argv, _ = fake.calls[0]
    assert "--user=%d:%d" % (uid, gid) in argv


def test_no_forbidden_host_access_flag_ever_appears(tmp_path):
    fake = FakeRunner(
        [
            CommandResult(0, b"", b"", False),
            CommandResult(0, b"pry-1\n", b"", False),
            CommandResult(0, b"pry-sidecar\n", b"", False),
        ]
    )
    docker = DockerRunner(runner=fake, uid=501, gid=20)
    script = tmp_path / "sidecar.py"
    script.write_text("")

    docker.build("img", tmp_path, ["true"])
    docker.start("img", tmp_path, "pry-1", ["true"], 3000)
    docker.start_sidecar("pry-net", "pry-sidecar", script)
    docker.create_network("pry-net")
    docker.remove_network("pry-net")

    for argv, _ in fake.calls:
        assert "-p" not in argv
        assert "-P" not in argv
        for token in argv:
            for forbidden in FORBIDDEN:
                assert forbidden not in token, (forbidden, argv)


def test_build_nonzero_is_build_failed(tmp_path):
    fake = FakeRunner([CommandResult(7, b"", b"npm ERR!", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).build("img", tmp_path, ["npm", "ci"])

    assert exc.value.cause == BUILD_FAILED


def test_build_timeout_is_build_failed(tmp_path):
    fake = FakeRunner([CommandResult(-1, b"", b"", True)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).build("img", tmp_path, ["npm", "ci"])

    assert exc.value.cause == BUILD_FAILED


def test_build_daemon_down_is_docker_unavailable(tmp_path):
    fake = FakeRunner(
        [
            CommandResult(
                1,
                b"",
                b"Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
                False,
            )
        ]
    )

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).build("img", tmp_path, ["true"])

    assert exc.value.cause == DOCKER_UNAVAILABLE


def test_start_nonzero_is_start_failed(tmp_path):
    fake = FakeRunner([CommandResult(125, b"", b"port exploded", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).start(
            "img", tmp_path, "pry-1", ["npm", "run", "start"], 3000
        )

    assert exc.value.cause == START_FAILED


def test_start_without_container_id_is_start_failed(tmp_path):
    fake = FakeRunner([CommandResult(0, b"", b"", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).start(
            "img", tmp_path, "pry-1", ["npm", "run", "start"], 3000
        )

    assert exc.value.cause == START_FAILED


def test_create_network_uses_the_internal_flag():
    fake = FakeRunner([CommandResult(0, b"", b"", False)])

    DockerRunner(runner=fake).create_network("pry-abc")

    assert fake.calls[0][0] == [
        "docker",
        "network",
        "create",
        "--internal",
        "pry-abc",
    ]


def test_create_network_failure_is_sandbox_error():
    fake = FakeRunner([CommandResult(1, b"", b"network already exists", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).create_network("pry-abc")

    assert exc.value.cause == SANDBOX_ERROR


def test_remove_network_tolerates_a_missing_network():
    fake = FakeRunner(
        [CommandResult(1, b"", b"Error: No such network: pry-abc", False)]
    )

    DockerRunner(runner=fake).remove_network("pry-abc")

    assert fake.calls[0][0] == ["docker", "network", "rm", "pry-abc"]


def test_remove_network_other_failure_is_sandbox_error():
    fake = FakeRunner([CommandResult(1, b"", b"permission denied", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).remove_network("pry-abc")

    assert exc.value.cause == SANDBOX_ERROR


def test_start_on_a_probe_network_uses_the_app_alias(tmp_path):
    fake = FakeRunner([CommandResult(0, b"container123\n", b"", False)])
    workspace = tmp_path / "copy"

    container = DockerRunner(runner=fake, uid=501, gid=20).start(
        "node:22-bookworm-slim",
        workspace,
        "pry-abc",
        ["npm", "run", "start"],
        3000,
        network="pry-abc",
        alias="app",
    )

    assert container == "container123"
    argv, _ = fake.calls[0]
    assert "--network=pry-abc" in argv
    assert "--network-alias=app" in argv
    assert "--network=none" not in argv
    assert "-p" not in argv
    assert "-P" not in argv
    _assert_security(argv)
    _pair(argv, "-e", "PORT=3000")


def test_start_without_an_alias_has_no_network_alias(tmp_path):
    fake = FakeRunner([CommandResult(0, b"container123\n", b"", False)])

    DockerRunner(runner=fake, uid=501, gid=20).start(
        "node:22-bookworm-slim",
        tmp_path,
        "pry-abc",
        ["npm", "run", "start"],
        3000,
        network="pry-abc",
    )

    argv, _ = fake.calls[0]
    assert "--network=pry-abc" in argv
    assert not any(token.startswith("--network-alias") for token in argv)


def test_start_sidecar_joins_the_network_with_security_flags_only(tmp_path):
    fake = FakeRunner([CommandResult(0, b"sidecar123\n", b"", False)])
    script = tmp_path / "sidecar.py"
    script.write_text("")

    container = DockerRunner(runner=fake, uid=501, gid=20).start_sidecar(
        "pry-abc", "pry-sidecar", script
    )

    assert container == "sidecar123"
    argv, _ = fake.calls[0]
    assert argv[:3] == ["docker", "run", "-d"]
    _pair(argv, "--name", "pry-sidecar")
    assert "--network=pry-abc" in argv
    assert "--network=none" not in argv
    assert "-p" not in argv
    assert "-P" not in argv
    _assert_security(argv)
    _pair(argv, "-v", "%s:/pry/sidecar.py:ro" % script)
    assert argv[-4:] == [
        "python:3.9-slim",
        "python",
        "-c",
        "import time; time.sleep(86400)",
    ]


def test_start_sidecar_accepts_a_custom_image(tmp_path):
    fake = FakeRunner([CommandResult(0, b"sidecar123\n", b"", False)])
    script = tmp_path / "sidecar.py"
    script.write_text("")

    DockerRunner(runner=fake).start_sidecar(
        "pry-abc", "pry-sidecar", script, image="python:3.13-slim"
    )

    argv, _ = fake.calls[0]
    assert argv[-4] == "python:3.13-slim"


def test_start_sidecar_nonzero_is_start_failed(tmp_path):
    fake = FakeRunner([CommandResult(125, b"", b"no such image", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).start_sidecar(
            "pry-abc", "pry-sidecar", tmp_path / "sidecar.py"
        )

    assert exc.value.cause == START_FAILED


def test_start_sidecar_mounts_an_idor_config_read_only(tmp_path):
    fake = FakeRunner([CommandResult(0, b"sidecar123\n", b"", False)])
    script = tmp_path / "sidecar.py"
    script.write_text("")
    config = tmp_path / "idor.json"
    config.write_text("{}")
    os.chmod(str(config), 0o600)

    DockerRunner(runner=fake, uid=501, gid=20).start_sidecar(
        "pry-abc", "pry-sidecar", script, config_path=config
    )

    argv, _ = fake.calls[0]
    _pair(argv, "-v", "%s:/pry-config/idor.json:ro" % config)
    _pair(argv, "-v", "%s:/pry/sidecar.py:ro" % script)
    _assert_security(argv)
    assert "-p" not in argv
    assert "-P" not in argv
    for token in argv:
        for forbidden in FORBIDDEN:
            assert forbidden not in token, (forbidden, argv)


def test_start_sidecar_mounts_a_write_config_read_only(tmp_path):
    fake = FakeRunner([CommandResult(0, b"sidecar123\n", b"", False)])
    script = tmp_path / "sidecar.py"
    script.write_text("")
    config = tmp_path / "write.json"
    config.write_text("{}")
    os.chmod(str(config), 0o600)

    DockerRunner(runner=fake, uid=501, gid=20).start_sidecar(
        "pry-abc", "pry-sidecar", script, write_config_path=config
    )

    argv, _ = fake.calls[0]
    _pair(argv, "-v", "%s:/pry-config/write.json:ro" % config)
    _pair(argv, "-v", "%s:/pry/sidecar.py:ro" % script)
    _assert_security(argv)
    assert "-p" not in argv
    assert "-P" not in argv


def test_start_sidecar_mounts_the_idor_and_write_configs_together(tmp_path):
    fake = FakeRunner([CommandResult(0, b"sidecar123\n", b"", False)])
    script = tmp_path / "sidecar.py"
    script.write_text("")
    idor = tmp_path / "idor.json"
    idor.write_text("{}")
    os.chmod(str(idor), 0o600)
    write = tmp_path / "write.json"
    write.write_text("{}")
    os.chmod(str(write), 0o600)

    DockerRunner(runner=fake, uid=501, gid=20).start_sidecar(
        "pry-abc",
        "pry-sidecar",
        script,
        config_path=idor,
        write_config_path=write,
    )

    argv, _ = fake.calls[0]
    _pair(argv, "-v", "%s:/pry-config/idor.json:ro" % idor)
    _pair(argv, "-v", "%s:/pry-config/write.json:ro" % write)
    _assert_security(argv)


def test_start_sidecar_without_a_config_mounts_no_config(tmp_path):
    fake = FakeRunner([CommandResult(0, b"sidecar123\n", b"", False)])
    script = tmp_path / "sidecar.py"
    script.write_text("")

    DockerRunner(runner=fake).start_sidecar("pry-abc", "pry-sidecar", script)

    argv, _ = fake.calls[0]
    assert not any("/pry-config" in token for token in argv)


def test_start_callback_sidecar_mounts_the_probe_dir_read_only(tmp_path):
    fake = FakeRunner([CommandResult(0, b"callback123\n", b"", False)])
    source_dir = tmp_path / "probe"

    container = DockerRunner(runner=fake, uid=501, gid=20).start_callback_sidecar(
        "pry-abc", "pry-callback-1", source_dir
    )

    assert container == "callback123"
    argv, _ = fake.calls[0]
    assert argv[:5] == ["docker", "run", "-d", "--name", "pry-callback-1"]
    assert "--network=pry-abc" in argv
    assert "--network-alias=pry-callback" in argv
    assert "--network=none" not in argv
    _pair(argv, "-v", "%s:/pry:ro" % source_dir)
    _assert_security(argv)
    assert argv[-3:] == ["python:3.9-slim", "python", "/pry/callback_server.py"]
    assert "-p" not in argv
    assert "-P" not in argv
    for token in argv:
        for forbidden in FORBIDDEN:
            assert forbidden not in token, (forbidden, argv)


def test_start_callback_sidecar_accepts_a_custom_image(tmp_path):
    fake = FakeRunner([CommandResult(0, b"callback123\n", b"", False)])

    DockerRunner(runner=fake).start_callback_sidecar(
        "pry-abc", "pry-callback-1", tmp_path, image="python:3.13-slim"
    )

    argv, _ = fake.calls[0]
    assert argv[-3] == "python:3.13-slim"


def test_start_callback_sidecar_without_an_id_is_start_failed(tmp_path):
    fake = FakeRunner([CommandResult(0, b"", b"", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).start_callback_sidecar(
            "pry-abc", "pry-callback-1", tmp_path
        )

    assert exc.value.cause == START_FAILED


def test_node_readiness_uses_fetch_and_any_http_response_is_ready():
    command = readiness_command("node", 3000)

    assert command[:2] == ["node", "-e"]
    script = command[2]
    assert "fetch(" in script
    assert "http://127.0.0.1:3000/" in script
    assert "process.exit(0)" in script
    assert "process.exit(1)" in script


def test_static_readiness_uses_urllib_and_treats_http_error_as_ready():
    command = readiness_command("static", 8000)

    assert command[:2] == ["python", "-c"]
    script = command[2]
    assert "urllib.request" in script
    assert "http://127.0.0.1:8000/" in script
    assert "except urllib.error.HTTPError:\n    sys.exit(0)" in script
    assert "except Exception:\n    sys.exit(1)" in script


def test_readiness_command_rejects_unknown_kind():
    with pytest.raises(IntakeError) as exc:
        readiness_command("python", 8000)

    assert exc.value.cause == SANDBOX_ERROR


def test_wait_ready_polls_inside_the_container_until_success():
    fake = FakeRunner(
        [
            CommandResult(1, b"", b"connection refused", False),
            CommandResult(0, b"true\n", b"", False),
            CommandResult(0, b"", b"", False),
        ]
    )

    DockerRunner(runner=fake).wait_ready(
        "pry-1", "node", 3000, timeout=1, interval=0.001
    )

    assert fake.calls[0][0] == ["docker", "exec", "pry-1"] + readiness_command(
        "node", 3000
    )
    assert fake.calls[1][0] == [
        "docker",
        "inspect",
        "--format",
        "{{.State.Running}}",
        "pry-1",
    ]
    assert fake.calls[2][0] == ["docker", "exec", "pry-1"] + readiness_command(
        "node", 3000
    )
    assert "-p" not in fake.calls[0][0]


def test_wait_ready_container_exited_is_start_failed():
    fake = FakeRunner(
        [
            CommandResult(1, b"", b"connection refused", False),
            CommandResult(0, b"false\n", b"", False),
        ]
    )

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).wait_ready(
            "pry-1", "node", 3000, timeout=60, interval=0.001
        )

    assert exc.value.cause == START_FAILED


def test_wait_ready_deadline_is_ready_timeout():
    fake = FakeRunner(
        [
            CommandResult(1, b"", b"connection refused", False),
            CommandResult(0, b"true\n", b"", False),
        ]
    )

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).wait_ready(
            "pry-1", "static", 8000, timeout=0, interval=0.001
        )

    assert exc.value.cause == READY_TIMEOUT


def test_wait_ready_daemon_down_is_docker_unavailable():
    fake = FakeRunner(
        [CommandResult(1, b"", b"Cannot connect to the Docker daemon", False)]
    )

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).wait_ready(
            "pry-1", "node", 3000, timeout=1, interval=0.001
        )

    assert exc.value.cause == DOCKER_UNAVAILABLE


def test_logs_returns_stdout_and_stderr_bytes():
    fake = FakeRunner([CommandResult(0, b"stdout\n", b"stderr\n", False)])

    assert DockerRunner(runner=fake).logs("pry-1") == b"stdout\nstderr\n"
    assert fake.calls[0][0] == ["docker", "logs", "pry-1"]


def test_logs_failure_is_sandbox_error():
    fake = FakeRunner([CommandResult(1, b"", b"no such container", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).logs("pry-1")

    assert exc.value.cause == SANDBOX_ERROR


def test_remove_tolerates_a_missing_container():
    fake = FakeRunner(
        [CommandResult(1, b"", b"Error: No such container: pry-1", False)]
    )

    DockerRunner(runner=fake).remove("pry-1")

    assert fake.calls[0][0] == ["docker", "rm", "-f", "pry-1"]


def test_remove_other_failure_is_sandbox_error():
    fake = FakeRunner([CommandResult(1, b"", b"permission denied", False)])

    with pytest.raises(IntakeError) as exc:
        DockerRunner(runner=fake).remove("pry-1")

    assert exc.value.cause == SANDBOX_ERROR


def test_subprocess_runner_returns_code_and_output():
    result = SubprocessRunner().run([sys.executable, "-c", "print('hi')"], 10)

    assert result.returncode == 0
    assert result.stdout == b"hi\n"
    assert result.timed_out is False


def test_subprocess_runner_marks_a_timeout():
    result = SubprocessRunner().run(
        [sys.executable, "-c", "import time; time.sleep(5)"], 0.05
    )

    assert result.timed_out is True
    assert result.returncode != 0


def test_subprocess_runner_maps_a_missing_binary_to_a_nonzero_result():
    result = SubprocessRunner().run(["/definitely/not/a/binary"], 5)

    assert result.returncode != 0
    assert result.timed_out is False
    assert result.stderr
