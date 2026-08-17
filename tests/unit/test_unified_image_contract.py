from pathlib import Path

from localstack import constants
from localstack.utils.bootstrap import get_docker_image_to_start

PROJECT_ROOT = Path(__file__).parents[2]


def test_docker_image_has_one_unified_edition_marker():
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text()

    assert "ARG LOCALSTACK_BUILD_VERSION=0.0.0.dev0" in dockerfile
    assert "/usr/lib/localstack/.unified-version" in dockerfile
    assert "/usr/lib/localstack/.community-version" not in dockerfile
    assert "/usr/lib/localstack/.pro-version" not in dockerfile
    assert "SERVICES=" not in dockerfile


def test_entrypoint_does_not_split_community_and_pro_images():
    entrypoint = (PROJECT_ROOT / "bin/docker-entrypoint.sh").read_text()

    assert "Community Docker image" not in entrypoint
    assert "dedicated Pro image" not in entrypoint
    assert "localstack/localstack-pro" not in entrypoint


def test_compose_files_use_the_same_image_without_a_required_license_token():
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text()

    assert "image: localstack/localstack" in compose
    assert not (PROJECT_ROOT / "docker-compose-pro.yml").exists()


def test_only_the_unified_image_constant_is_exposed():
    assert constants.DOCKER_IMAGE_NAME == "localstack/localstack"
    assert not hasattr(constants, "DOCKER_IMAGE_NAME_PRO")
    assert not hasattr(constants, "DOCKER_IMAGE_NAME_FULL")
    assert constants.OFFICIAL_IMAGES == [constants.DOCKER_IMAGE_NAME]


def test_auth_token_never_selects_a_different_image(monkeypatch):
    monkeypatch.delenv("IMAGE_NAME", raising=False)
    monkeypatch.setenv("LOCALSTACK_AUTH_TOKEN", "configured-but-not-an-image-selector")

    assert get_docker_image_to_start() == constants.DOCKER_IMAGE_NAME

    monkeypatch.setenv("IMAGE_NAME", "internal-registry/localstack:approved")
    assert get_docker_image_to_start() == "internal-registry/localstack:approved"
