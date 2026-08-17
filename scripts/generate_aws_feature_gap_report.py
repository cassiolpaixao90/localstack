#!/usr/bin/env python3
"""Generate the consolidated AWS and AWS CDK feature-gap report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

API_CATALOG_PATH = Path("capabilities/generated/capabilities.json")
CDK_SERVICE_MAP_PATH = Path("capabilities/cdk/services.json")
CDK_COMPATIBILITY_PATH = Path("capabilities/cdk/compatibility.json")
DEFAULT_OUTPUT_PATH = Path("capabilities/aws-feature-gap-report.md")

MAX_API_CATALOG_BYTES = 4 * 1024 * 1024
MAX_CDK_SERVICE_MAP_BYTES = 2 * 1024 * 1024
MAX_CDK_COMPATIBILITY_BYTES = 64 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024

OPERATION_STATUSES = ("missing", "scaffold", "fallback", "partial", "native", "parity-pass")


def _read_regular_bounded(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} is not a regular file")
        if metadata.st_size < 1 or metadata.st_size > maximum:
            raise ValueError(f"{label} is outside the accepted size")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            payload = stream.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) != metadata.st_size or len(payload) > maximum:
        raise ValueError(f"{label} changed while being read")
    return payload


def _load_json(path: Path, maximum: int, label: str) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular_bounded(path, maximum, label)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ValueError(f"{label} is not valid bounded JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain an object")
    return value, payload


def _canonical_digest(
    value: dict[str, Any], digest_field: str, *, retain_empty_field: bool = False
) -> str:
    payload = dict(value)
    declared = payload.get(digest_field)
    if retain_empty_field:
        payload[digest_field] = ""
    else:
        payload.pop(digest_field, None)
    calculated = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    if declared != calculated:
        raise ValueError(f"invalid {digest_field}")
    return calculated


def _file_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _percentage(value: int, total: int) -> str:
    return f"{value / total * 100:.2f}%" if total else "0.00%"


def _cell(values: list[str]) -> str:
    return "<br>".join(f"`{value}`" for value in values) if values else "-"


def _api_counts(service: dict[str, Any]) -> dict[str, int]:
    statuses = service["operation_statuses"]
    return {status: len(statuses[status]) for status in OPERATION_STATUSES}


def _validate_inputs(
    api_catalog: dict[str, Any],
    cdk_map: dict[str, Any],
    compatibility: dict[str, Any],
) -> None:
    _canonical_digest(api_catalog, "inventory_sha256")
    _canonical_digest(cdk_map, "map_sha256", retain_empty_field=True)
    _canonical_digest(compatibility, "manifest_sha256")

    services = api_catalog.get("services")
    if not isinstance(services, dict) or len(services) != api_catalog["summary"]["services"]:
        raise ValueError("API service summary does not match the catalog")
    totals = Counter()
    for service in services.values():
        counts = _api_counts(service)
        totals.update(counts)
    if dict(totals) != api_catalog["summary"]["by_status"]:
        raise ValueError("API operation totals do not match the catalog")

    cdk_services = cdk_map.get("services")
    if (
        not isinstance(cdk_services, list)
        or len(cdk_services) != cdk_map["summary"]["cdk_service_modules"]
    ):
        raise ValueError("CDK service summary does not match the map")
    modules = [service["module"] for service in cdk_services]
    if modules != sorted(modules) or len(modules) != len(set(modules)):
        raise ValueError("CDK services are not unique and ordered")
    cdk_summary = cdk_map["summary"]
    if cdk_summary["resource_provider_schema_declared_handlers"] != sum(
        cdk_summary[key]
        for key in (
            "resource_provider_handlers_method_body_present_unverified",
            "resource_provider_handlers_notimplemented_only",
            "resource_provider_handlers_contains_notimplemented",
            "resource_provider_handlers_method_missing",
        )
    ):
        raise ValueError("CDK handler status totals do not match declared handlers")
    if cdk_summary["localstack_cdk_l1_intersection"] != sum(
        cdk_summary[key]
        for key in (
            "resource_provider_records_all_method_bodies_present_unverified",
            "resource_provider_records_incomplete_static_handler_surface",
            "resource_provider_records_no_schema_handler_declarations",
        )
    ):
        raise ValueError("CDK provider handler record totals do not match the intersection")


def render_report(
    api_catalog: dict[str, Any],
    api_payload: bytes,
    cdk_map: dict[str, Any],
    cdk_payload: bytes,
    compatibility: dict[str, Any],
    compatibility_payload: bytes,
) -> str:
    api_summary = api_catalog["summary"]
    cdk_summary = cdk_map["summary"]
    total_operations = api_summary["operations"]
    by_status = api_summary["by_status"]
    non_missing_operations = total_operations - by_status["missing"]

    service_tiers = Counter()
    services_with_any_path = 0
    for service in api_catalog["services"].values():
        counts = _api_counts(service)
        if counts["missing"] == sum(counts.values()):
            service_tiers["fully-missing"] += 1
            continue
        services_with_any_path += 1
        highest = next(status for status in reversed(OPERATION_STATUSES) if counts[status])
        service_tiers[highest] += 1

    lines = [
        "# Relatorio completo de lacunas AWS e AWS CDK",
        "",
        "> Arquivo gerado. Nao edite manualmente. Inventario estatico identifica caminhos candidatos; nao comprova paridade com a AWS.",
        "",
        "## Veredito executivo",
        "",
        "O checkout ainda nao oferece todas as features AWS. A maior parte do denominador Botocore nao possui caminho de implementacao neste repositorio, e nenhum operation status foi promovido para `native` ou `parity-pass` por evidencia runtime diferencial.",
        "",
        f"- **{by_status['missing']:,} de {total_operations:,} operacoes ({_percentage(by_status['missing'], total_operations)})** estao `missing`.",
        f"- **{non_missing_operations:,} operacoes ({_percentage(non_missing_operations, total_operations)})** possuem somente algum caminho estatico (`scaffold`, fallback ou provider parcial).",
        f"- **{services_with_any_path} de {api_summary['services']} servicos** possuem algum caminho estatico; {service_tiers['fully-missing']} estao integralmente ausentes no inventario local.",
        f"- **{cdk_summary['localstack_cdk_l1_intersection']:,} de {cdk_summary['cdk_l1_resource_types']:,} recursos CDK L1 ({cdk_summary['static_l1_coverage_basis_points'] / 100:.2f}%)** resolvem para um resource provider LocalStack registrado.",
        f"- O mapa CDK tem {cdk_summary['modules_static_complete']} namespaces estaticamente completos, {cdk_summary['modules_static_partial']} parciais e {cdk_summary['modules_static_none']} sem provider registrado.",
        f"- Dos **{cdk_summary['resource_provider_schema_declared_handlers']:,} handlers declarados** nos schemas dos providers CDK, somente **{cdk_summary['resource_provider_handlers_method_body_present_unverified']:,}** possuem corpo direto sem `NotImplementedError` detectavel; isso continua sem comprovar comportamento.",
        "- `available` no endpoint de health significa que o servico foi carregado; nao significa cobertura total, CRUD completo, rollback correto ou paridade AWS.",
        "",
        "## Fontes content-addressed",
        "",
        "| Fonte | Versao/claim | SHA-256 dos bytes | Digest semantico |",
        "|---|---|---|---|",
        f"| `{API_CATALOG_PATH}` | Botocore `{api_catalog['source']['version']}` | `{_file_digest(api_payload)}` | `{api_catalog['inventory_sha256']}` |",
        f"| `{CDK_SERVICE_MAP_PATH}` | aws-cdk-lib `{cdk_map['sources']['aws_cdk_lib']['version']}` / `{cdk_map['claim']}` | `{_file_digest(cdk_payload)}` | `{cdk_map['map_sha256']}` |",
        f"| `{CDK_COMPATIBILITY_PATH}` | schema `{compatibility['schema_version']}` | `{_file_digest(compatibility_payload)}` | `{compatibility['manifest_sha256']}` |",
        "",
        "## Lacunas de operacoes AWS",
        "",
        "| Status | Quantidade | Percentual | Interpretacao |",
        "|---|---:|---:|---|",
        f"| `missing` | {by_status['missing']:,} | {_percentage(by_status['missing'], total_operations)} | Sem interface/provider classificado neste checkout |",
        f"| `scaffold` | {by_status['scaffold']:,} | {_percentage(by_status['scaffold'], total_operations)} | Handler gerado sem implementacao ou fallback |",
        f"| `fallback` | {by_status['fallback']:,} | {_percentage(by_status['fallback'], total_operations)} | Delegacao Moto/HTTP; comportamento e estado podem divergir |",
        f"| `partial` | {by_status['partial']:,} | {_percentage(by_status['partial'], total_operations)} | Override existe, mas runtime/paridade nao foram promovidos |",
        f"| `native` | {by_status['native']:,} | {_percentage(by_status['native'], total_operations)} | Exige evidencia runtime nativa |",
        f"| `parity-pass` | {by_status['parity-pass']:,} | {_percentage(by_status['parity-pass'], total_operations)} | Exige diferencial AWS recente e sem exclusoes criticas |",
        "",
        "### Distribuicao dos servicos pelo melhor nivel encontrado",
        "",
        "| Melhor nivel estatico | Servicos |",
        "|---|---:|",
    ]
    for tier in ("fully-missing", "scaffold", "fallback", "partial", "native", "parity-pass"):
        lines.append(f"| `{tier}` | {service_tiers[tier]} |")

    lines.extend(
        [
            "",
            "## CloudFormation e AWS CDK",
            "",
            f"- Modulos CDK inventariados: **{cdk_summary['cdk_service_modules']:,}**.",
            f"- Modulos com L1: **{cdk_summary['modules_with_l1_resources']:,}**; modulos auxiliares/L2 sem L1 proprio: **{cdk_summary['modules_without_l1_resources']:,}**.",
            f"- Tipos CDK L1: **{cdk_summary['cdk_l1_resource_types']:,}**.",
            f"- Tipos no catalogo CloudFormation local: **{cdk_summary['current_cfn_catalog_resource_types']:,}**.",
            f"- Intersecao CDK/catalogo CFN: **{cdk_summary['cdk_current_cfn_overlap']:,}**.",
            f"- Tipos CDK ausentes do catalogo CFN local: **{cdk_summary['cdk_only_resource_types']:,}**.",
            f"- Tipos CFN locais ausentes do aws-cdk-lib pinado: **{cdk_summary['current_cfn_only_resource_types']:,}**.",
            f"- Modulos L1 sem candidato de API: **{cdk_summary['modules_l1_without_api_catalog_candidate']:,}**.",
            f"- Providers CDK cujos handlers declarados possuem todos os corpos presentes (nao verificados): **{cdk_summary['resource_provider_records_all_method_bodies_present_unverified']:,}**; com superficie estatica incompleta: **{cdk_summary['resource_provider_records_incomplete_static_handler_surface']:,}**; sem declaracoes de handlers no schema: **{cdk_summary['resource_provider_records_no_schema_handler_declarations']:,}**.",
            f"- Lacunas de handler declaradas: **{cdk_summary['resource_provider_handlers_notimplemented_only']:,}** stubs exatos, **{cdk_summary['resource_provider_handlers_contains_notimplemented']:,}** corpo parcial contendo `NotImplementedError` e **{cdk_summary['resource_provider_handlers_method_missing']:,}** metodos ausentes.",
            "",
            "### Drift de tipos",
            "",
            "**Somente no CDK pinado:**",
            "",
            _cell(cdk_map["drift"]["cdk_only_resource_types"]),
            "",
            "**Somente no catalogo CloudFormation local:**",
            "",
            _cell(cdk_map["drift"]["current_cfn_only_resource_types"]),
            "",
            "### Namespaces CDK ainda sem candidato de API",
            "",
            "| Modulo | Namespaces CFN sem mapeamento | L1s |",
            "|---|---|---:|",
        ]
    )
    for service in cdk_map["services"]:
        if service["unmapped_cloudformation_namespaces"]:
            lines.append(
                f"| `{service['module']}` | {_cell(service['unmapped_cloudformation_namespaces'])} | {service['l1_class_count']} |"
            )

    lines.extend(
        [
            "",
            "## Evidencia CDK atual",
            "",
            "### Cenarios reais de CLI retidos",
            "",
            "| Cenario | Status | Linguagem | Plataformas | Limitacoes |",
            "|---|---|---|---|---|",
        ]
    )
    for scenario in compatibility["execution_scenarios"]:
        language = scenario["construct_language"] or "language-neutral"
        lines.append(
            f"| `{scenario['id']}` | `{scenario['status']}` | `{language}` | {_cell(scenario['platforms'])} | {_cell(scenario['limitations'])} |"
        )

    lines.extend(
        [
            "",
            "### Matriz de capacidades CDK",
            "",
            "| Capacidade | Status | Linguagens | Lacunas declaradas |",
            "|---|---|---|---|",
        ]
    )
    for capability in compatibility["capabilities"]:
        lines.append(
            f"| `{capability['id']}` | `{capability['status']}` | {_cell(capability['languages'])} | {_cell(capability['gaps'])} |"
        )

    lines.extend(
        [
            "",
            "## Backlog recomendado",
            "",
            f"1. **Converter presenca estatica em evidencia lifecycle:** create/read/update/no-op/delete, rollback, falha parcial e cleanup para os {cdk_summary['modules_static_complete']} namespaces CDK estaticamente completos.",
            "2. **Fechar os menores gaps de resource providers:** priorizar modulos parciais com um ou dois tipos ausentes e APIs locais ja mapeadas.",
            "3. **Reduzir fallback:** substituir caminhos Moto/HTTP onde ownership, idempotencia ou consistencia diferem da AWS.",
            "4. **Abrir os servicos integralmente ausentes:** priorizar demanda real e dependencias centrais; nao usar apenas contagem bruta de operacoes.",
            "5. **Produzir evidencia AWS diferencial:** nenhum status pode virar `parity-pass` sem run AWS recente, JUnit exato, proveniencia e cleanup comprovado.",
            "6. **Manter packaging honesto:** uma imagem sem filtro de servicos nao implementa codigo que nao existe neste checkout e nao deve ser rotulada como feature-complete apenas pelo nome da tag.",
            "",
            "### Modulos CDK estaticamente completos que ainda precisam de evidencia runtime",
            "",
            "| Modulo | L1s | APIs candidatas |",
            "|---|---:|---|",
        ]
    )
    for service in cdk_map["services"]:
        if service["static_resource_provider_status"] == "complete":
            lines.append(
                f"| `{service['module']}` | {service['l1_class_count']} | {_cell([item['service'] for item in service['api_catalog']])} |"
            )

    lines.extend(
        [
            "",
            "### Modulos CDK parciais ordenados pelo menor gap",
            "",
            "| Modulo | Providers/L1s | Faltantes | Tipos faltantes |",
            "|---|---:|---:|---|",
        ]
    )
    partial_services = [
        service
        for service in cdk_map["services"]
        if service["static_resource_provider_status"] == "partial"
    ]
    partial_services.sort(
        key=lambda service: (len(service["missing_resource_provider_types"]), service["module"])
    )
    for service in partial_services:
        lines.append(
            f"| `{service['module']}` | {len(service['localstack_resource_provider_types'])}/{service['l1_class_count']} | {len(service['missing_resource_provider_types'])} | {_cell(service['missing_resource_provider_types'])} |"
        )

    lines.extend(
        [
            "",
            "## Anexo A — todos os servicos e operacoes por status",
            "",
            "A tabela cobre todos os servicos do Botocore pinado. Os nomes exatos das operacoes em cada grupo estao em `capabilities/generated/capabilities.json` em `/services/<service>/operation_statuses`; o relatorio nao duplica 17.854 nomes para permanecer revisavel.",
            "",
            "| Servico | Ops | Missing | Scaffold | Fallback | Partial | Native | Parity | Provider | CFN |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---|---:|",
        ]
    )
    for service_name, service in api_catalog["services"].items():
        counts = _api_counts(service)
        operations = sum(counts.values())
        lines.append(
            f"| `{service_name}` | {operations} | {counts['missing']} | {counts['scaffold']} | {counts['fallback']} | {counts['partial']} | {counts['native']} | {counts['parity-pass']} | `{service['default_provider'] or '-'}` | {len(service['cloudformation_resources'])} |"
        )

    lines.extend(
        [
            "",
            "## Anexo B — todos os modulos AWS CDK",
            "",
            "| Modulo | L1s | Providers | Faltantes | Estado estatico | API | Planejamento |",
            "|---|---:|---:|---:|---|---|---|",
        ]
    )
    for service in cdk_map["services"]:
        lines.append(
            f"| `{service['module']}` | {service['l1_class_count']} | {len(service['localstack_resource_provider_types'])} | {len(service['missing_resource_provider_types'])} | `{service['static_resource_provider_status']}` | `{service['api_mapping_status']}` | `{service['planning_status']}` |"
        )

    lines.extend(
        [
            "",
            "## Limites de interpretacao",
            "",
            "- A analise e conservadora e estatica. Um provider pode funcionar em cenarios nao promovidos, mas isso nao autoriza uma alegacao de suporte.",
            "- Presenca de handler/provider nao comprova validacao de parametros, erros, paginacao, concorrencia, persistencia, IAM, regioes, quotas ou fidelidade de eventos.",
            "- Fallback nao e equivalente a implementacao enterprise: ownership de estado e atualizacoes de dependencias podem alterar comportamento.",
            "- Cobertura CDK L1 nao mede L2/L3, assets, Docker, lookups, custom resources, transforms ou integracoes cross-service.",
            "- Os cenarios CDK promovidos sao estreitos; nao devem ser extrapolados para suporte global a `cdk bootstrap`, `synth`, `deploy` ou linguagens.",
            "- Este relatorio nao concede acesso a codigo privado ausente, nao contorna licencas e nao transforma uma imagem `community` em feature-complete.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_atomic(path: Path, content: str) -> None:
    payload = content.encode()
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("generated report exceeds the accepted size")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    project_root = Path(args.project_root).resolve()
    output_path = project_root / args.output
    try:
        api_catalog, api_payload = _load_json(
            project_root / API_CATALOG_PATH, MAX_API_CATALOG_BYTES, "API catalog"
        )
        cdk_map, cdk_payload = _load_json(
            project_root / CDK_SERVICE_MAP_PATH, MAX_CDK_SERVICE_MAP_BYTES, "CDK service map"
        )
        compatibility, compatibility_payload = _load_json(
            project_root / CDK_COMPATIBILITY_PATH,
            MAX_CDK_COMPATIBILITY_BYTES,
            "CDK compatibility manifest",
        )
        _validate_inputs(api_catalog, cdk_map, compatibility)
        report = render_report(
            api_catalog,
            api_payload,
            cdk_map,
            cdk_payload,
            compatibility,
            compatibility_payload,
        )
        if args.check:
            current = _read_regular_bounded(output_path, MAX_REPORT_BYTES, "feature gap report")
            if current != report.encode():
                print("AWS feature gap report is stale", file=sys.stderr)
                return 1
        else:
            _write_atomic(output_path, report)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 2
    print(f"{'verified' if args.check else 'generated'} {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
