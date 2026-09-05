#!/usr/bin/env python3
"""
cti_cloud_arch.py — opt-in cloud-architecture figure for CTI reports, applying the
Diagram AI Generator approach (https://github.com/carlosmgv02/diagram-ai-generator):
its JSON spec shape (provider / components{type,category} / connections) rendered
through the `diagrams` library with real provider icons (AWS/Azure/GCP/K8s) via
graphviz.

It is CLOUD-GATED and best-effort by design: it only produces a figure when a
case's subjects/findings actually reveal cloud infrastructure (S3, EC2, RDS, Azure
Blob, GCS, GKE, …). Generic OSINT entities never trigger it. It also degrades
silently when graphviz or the `diagrams` package is unavailable, or when disabled
with CTI_CLOUD_ARCH=0.

Rendering runs in an isolated `uv run --with diagrams` subprocess so the heavy
`diagrams` package (≈33 MB of icons) never has to be a dependency of the main
HTML/DOCX generators. graphviz (the `dot` binary) is a system dependency handled
by the skill installer.

Public API:
    detect_components(data) -> list[dict]      # [] when no cloud infra
    build_cloud_png(data)   -> (bytes|None, note)

Author: CTI Expert
"""
import base64
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cti_timeouts import CALL_TIMEOUT  # noqa: E402 — per-call ceiling (CTI_CALL_TIMEOUT)

# keyword -> (diagrams class import path, display label). Short tokens (<=4 chars)
# are matched on word boundaries to avoid false hits.
CLOUD_NODES = {
    "aws": {
        "s3": ("diagrams.aws.storage.S3", "S3"),
        "ec2": ("diagrams.aws.compute.EC2", "EC2"),
        "lambda": ("diagrams.aws.compute.Lambda", "Lambda"),
        "ecs": ("diagrams.aws.compute.ECS", "ECS"),
        "eks": ("diagrams.aws.compute.EKS", "EKS"),
        "rds": ("diagrams.aws.database.RDS", "RDS"),
        "dynamodb": ("diagrams.aws.database.Dynamodb", "DynamoDB"),
        "elasticache": ("diagrams.aws.database.Elasticache", "ElastiCache"),
        "cloudfront": ("diagrams.aws.network.CloudFront", "CloudFront"),
        "route53": ("diagrams.aws.network.Route53", "Route 53"),
        "route 53": ("diagrams.aws.network.Route53", "Route 53"),
        "api gateway": ("diagrams.aws.network.APIGateway", "API Gateway"),
        "apigateway": ("diagrams.aws.network.APIGateway", "API Gateway"),
        "alb": ("diagrams.aws.network.ELB", "ALB"),
        "elb": ("diagrams.aws.network.ELB", "ELB"),
        "sqs": ("diagrams.aws.integration.SQS", "SQS"),
        "iam": ("diagrams.aws.security.IAM", "IAM"),
    },
    "azure": {
        "blob storage": ("diagrams.azure.storage.BlobStorage", "Blob Storage"),
        "azure blob": ("diagrams.azure.storage.BlobStorage", "Blob Storage"),
        "function app": ("diagrams.azure.compute.FunctionApps", "Functions"),
        "azure functions": ("diagrams.azure.compute.FunctionApps", "Functions"),
        "azure vm": ("diagrams.azure.compute.VM", "VM"),
        "aks": ("diagrams.azure.compute.AKS", "AKS"),
        "cosmos db": ("diagrams.azure.database.CosmosDb", "Cosmos DB"),
    },
    "gcp": {
        "gcs": ("diagrams.gcp.storage.Storage", "Cloud Storage"),
        "cloud storage": ("diagrams.gcp.storage.Storage", "Cloud Storage"),
        "gke": ("diagrams.gcp.compute.KubernetesEngine", "GKE"),
        "gce": ("diagrams.gcp.compute.ComputeEngine", "Compute Engine"),
        "compute engine": ("diagrams.gcp.compute.ComputeEngine", "Compute Engine"),
        "cloud run": ("diagrams.gcp.compute.Run", "Cloud Run"),
        "bigquery": ("diagrams.gcp.analytics.Bigquery", "BigQuery"),
    },
    "k8s": {
        "kubernetes": ("diagrams.k8s.compute.Pod", "Pod"),
        "k8s": ("diagrams.k8s.compute.Pod", "Pod"),
        "ingress": ("diagrams.k8s.network.Ingress", "Ingress"),
    },
}


def _corpus(data):
    """All free text where cloud services might be named."""
    parts = []
    for s in data.get("subjects") or []:
        parts.append(str(s.get("label") or ""))
        parts.append(str(s.get("notes") or ""))
        parts.extend(str(a) for a in (s.get("aliases") or []))
    for f in data.get("findings") or []:
        parts.append(str(f.get("description") or ""))
        parts.append(str(f.get("source_url") or ""))
        parts.extend(str(t) for t in (f.get("tags") or []))
    return " \n ".join(parts).lower()


def detect_components(data):
    """Return de-duplicated cloud components as diagram-ai-generator-style specs.

    Each item: {id, provider, category, type, class_path, label}. Empty list when
    the case reveals no cloud infrastructure.
    """
    if not isinstance(data, dict):
        return []
    text = _corpus(data)
    found = []
    seen = set()
    for provider, table in CLOUD_NODES.items():
        for kw, (path, label) in table.items():
            if len(kw) <= 4:
                hit = re.search(r"\b" + re.escape(kw) + r"\b", text) is not None
            else:
                hit = kw in text
            if hit and path not in seen:
                seen.add(path)
                found.append({
                    "id": path.rsplit(".", 1)[-1].lower(),
                    "provider": provider,
                    "class_path": path,
                    "label": label,
                })
    return found[:10]


def _load_class(path):
    mod, name = path.rsplit(".", 1)
    try:
        return getattr(importlib.import_module(mod), name)
    except Exception:
        from diagrams.generic.blank import Blank
        return Blank


def render(data, out_png):
    """Render the detected cloud architecture to out_png (imports `diagrams`).

    Returns True on success. Must run where `diagrams` + graphviz are available
    (normally the `uv run --with diagrams` subprocess spawned by build_cloud_png).
    """
    comps = detect_components(data)
    if not comps:
        return False
    from diagrams import Diagram, Cluster  # noqa: E402

    case = data.get("case", {}) or {}
    subject = case.get("subject") or case.get("label") or "Target"
    stem = out_png[:-4] if out_png.lower().endswith(".png") else out_png
    graph_attr = {"bgcolor": "transparent", "pad": "0.4", "fontname": "sans-serif",
                  "fontsize": "11", "labelloc": "t"}
    node_attr = {"fontname": "sans-serif", "fontsize": "11"}
    edge_attr = {"color": "#4f5d75", "fontname": "sans-serif", "fontsize": "9"}

    by_provider = {}
    for c in comps:
        by_provider.setdefault(c["provider"], []).append(c)

    title = "Cloud Infrastructure — %s" % subject
    with Diagram(title, filename=stem, outformat="png", show=False, direction="LR",
                 graph_attr=graph_attr, node_attr=node_attr, edge_attr=edge_attr):
        from diagrams.generic.blank import Blank
        target = Blank(subject)
        for provider, items in by_provider.items():
            with Cluster(provider.upper()):
                nodes = [_load_class(c["class_path"])(c["label"]) for c in items]
            for n in nodes:
                target >> n
    return os.path.isfile(stem + ".png")


def build_cloud_png(data):
    """(png_bytes | None, note). Cloud-gated, dependency-safe, isolated subprocess.

    Skips (returns None) when: disabled via CTI_CLOUD_ARCH=0; no cloud infra found;
    graphviz (`dot`) missing; or the `diagrams` render fails.
    """
    if os.environ.get("CTI_CLOUD_ARCH", "1") == "0":
        return None, "disabled (CTI_CLOUD_ARCH=0)"
    comps = detect_components(data)
    if not comps:
        return None, "no cloud infrastructure detected"
    if not shutil.which("dot"):
        return None, "graphviz not installed (install graphviz to render cloud architecture)"

    tmp = tempfile.mkdtemp(prefix="cti-cloud-")
    case_path = os.path.join(tmp, "case.json")
    out_png = os.path.join(tmp, "cloud.png")
    try:
        with open(case_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        # Fast path: diagrams already importable in this interpreter.
        try:
            import diagrams  # noqa: F401
            ok = render(data, out_png)
        except Exception:
            ok = False
        if not ok:
            # Isolated subprocess so `diagrams` need not be a base dependency.
            runner = None
            if shutil.which("uv"):
                runner = ["uv", "run", "--with", "diagrams", "python3",
                          os.path.abspath(__file__), case_path, out_png]
            if runner:
                proc = subprocess.run(runner, capture_output=True, text=True, timeout=CALL_TIMEOUT)
                ok = proc.returncode == 0 and os.path.isfile(out_png)
                if not ok:
                    detail = (proc.stderr or proc.stdout or "").strip().splitlines()
                    return None, "render failed: %s" % (detail[-1] if detail else "unknown")
            else:
                return None, "the `diagrams` package is unavailable (install it or uv)"
        with open(out_png, "rb") as f:
            png = f.read()
        return png, "%d cloud component(s): %s" % (
            len(comps), ", ".join(sorted({c["provider"].upper() for c in comps})))
    except subprocess.TimeoutExpired:
        return None, "render timed out"
    except Exception as e:
        return None, "render error: %s" % e
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def png_data_uri(png):
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def main(argv):
    if len(argv) < 2:
        print("usage: cti_cloud_arch.py <case.json> <out.png>")
        return 2
    with open(argv[0], encoding="utf-8") as f:
        data = json.load(f)
    ok = render(data, argv[1])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
