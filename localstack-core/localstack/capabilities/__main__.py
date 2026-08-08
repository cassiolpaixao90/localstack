from __future__ import annotations

import argparse
import sys

from localstack.capabilities.catalog import generate_artifacts, parse_project_root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate the static AWS capability inventory")
    parser.add_argument("--project-root", default=".", help="LocalStack repository root")
    parser.add_argument("--output-dir", default="capabilities", help="artifact directory")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when committed artifacts differ; do not write files",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        project_root = parse_project_root(args.project_root)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    output_dir = (project_root / args.output_dir).resolve()
    artifacts = generate_artifacts(project_root)
    stale: list[str] = []

    for relative_path, content in artifacts.items():
        target = output_dir / relative_path
        if args.check:
            if not target.exists() or target.read_text() != content:
                stale.append(relative_path)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    if stale:
        print("capability artifacts are stale:", file=sys.stderr)
        for path in stale:
            print(f"  {path}", file=sys.stderr)
        return 1

    action = "verified" if args.check else "generated"
    print(f"{action} {len(artifacts)} capability artifacts in {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
