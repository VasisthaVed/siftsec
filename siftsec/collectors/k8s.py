# SPDX-License-Identifier: Apache-2.0
"""Read-only Kubernetes GPU runtime collector (Phase 5.1)."""

import re
from typing import Any

from siftsec.collectors.base import BaseCollector
from siftsec.config import SiftsecConfig, settings
from siftsec.engine.attrs import K8sNodeAttrs, K8sPodAttrs
from siftsec.engine.models import CloudProvider, CloudResource
from siftsec.errors import AISPMError

_IMAGE_TAG_VER_RE = re.compile(r":v?(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)")


class K8sCollector(BaseCollector):
    """Collects Kubernetes GPU nodes, NVIDIA GPU Operator DaemonSets, and GPU pods (read-only)."""

    def __init__(
        self,
        *,
        kube_context: str | None = None,
        cfg: SiftsecConfig | None = None,
        core_v1: Any = None,
        apps_v1: Any = None,
    ) -> None:
        self.cfg = cfg or settings
        self.kube_context = kube_context
        self._core_v1 = core_v1
        self._apps_v1 = apps_v1

    def _init_clients(self) -> tuple[Any, Any]:
        if self._core_v1 is not None and self._apps_v1 is not None:
            return self._core_v1, self._apps_v1
        try:
            from kubernetes import client, config  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AISPMError(
                "Kubernetes extra not installed. Run `pip install siftsec[k8s]`."
            ) from exc

        config.load_kube_config(context=self.kube_context)
        return client.CoreV1Api(), client.AppsV1Api()

    @staticmethod
    def _list_paginated(fn: Any, **kwargs: Any) -> list[Any]:
        items: list[Any] = []
        cont: str | None = None
        while True:
            resp = fn(limit=500, _continue=cont, **kwargs) if cont else fn(limit=500, **kwargs)
            items.extend(getattr(resp, "items", []) or [])
            meta = getattr(resp, "metadata", None)
            cont = getattr(meta, "_continue", None) if meta else None
            if not cont:
                return items

    def collect(self) -> list[CloudResource]:
        core_v1, apps_v1 = self._init_clients()
        nodes = self._list_paginated(core_v1.list_node)
        pods = self._list_paginated(core_v1.list_pod_for_all_namespaces)
        daemonsets = self._list_paginated(apps_v1.list_daemon_set_for_all_namespaces)

        # Infer NVIDIA Container Toolkit version from GPU operator DaemonSet image tags
        operator_toolkit_ver: str | None = None
        for ds in daemonsets:
            ds_name = str(getattr(getattr(ds, "metadata", None), "name", ""))
            if "nvidia-container-toolkit" in ds_name or "gpu-operator" in ds_name:
                containers = getattr(
                    getattr(getattr(ds, "spec", None), "template", None), "spec", None
                )
                for c in getattr(containers, "containers", []) or []:
                    img = str(getattr(c, "image", ""))
                    if "container-toolkit" in img:
                        m = _IMAGE_TAG_VER_RE.search(img)
                        if m:
                            operator_toolkit_ver = m.group(1)

        # Track namespaces scheduling GPU pods per node for multi-tenant time-slicing detection
        node_gpu_namespaces: dict[str, set[str]] = {}
        pod_resources: list[CloudResource] = []

        for pod in pods:
            meta = getattr(pod, "metadata", None)
            spec = getattr(pod, "spec", None)
            pod_name = str(getattr(meta, "name", "unknown"))
            ns = str(getattr(meta, "namespace", "default"))
            node_name = getattr(spec, "node_name", None)
            labels = dict(getattr(meta, "labels", None) or {})

            gpu_req = 0
            privileged = False
            images: list[str] = []
            all_digest = True
            for c in getattr(spec, "containers", []) or []:
                img = str(getattr(c, "image", ""))
                if img:
                    images.append(img)
                    if "@sha256:" not in img:
                        all_digest = False
                sc = getattr(c, "security_context", None)
                if sc and getattr(sc, "privileged", False):
                    privileged = True
                res_obj = getattr(c, "resources", None)
                limits = (getattr(res_obj, "limits", None) or {}) if res_obj else {}
                if "nvidia.com/gpu" in limits:
                    try:
                        gpu_req += int(limits["nvidia.com/gpu"])
                    except (ValueError, TypeError):
                        gpu_req += 1

            host_paths: list[str] = []
            for vol in getattr(spec, "volumes", []) or []:
                hp = getattr(vol, "host_path", None)
                if hp and getattr(hp, "path", None):
                    host_paths.append(str(hp.path))

            is_ai = gpu_req > 0 or any(
                k in str(labels).lower() for k in ("vllm", "triton", "torchserve", "ollama")
            )
            if gpu_req > 0 and node_name:
                node_gpu_namespaces.setdefault(str(node_name), set()).add(ns)

            if not is_ai:
                continue

            pod_sc = getattr(spec, "security_context", None)
            attrs = K8sPodAttrs(
                namespace=ns,
                node_name=str(node_name) if node_name else None,
                privileged=privileged,
                host_network=bool(getattr(spec, "host_network", False)),
                host_pid=bool(getattr(spec, "host_pid", False)),
                host_paths=host_paths,
                gpu_requested=gpu_req,
                images=images,
                all_images_use_digest=all_digest,
                run_as_non_root=getattr(pod_sc, "run_as_non_root", None) if pod_sc else None,
                runtime_class_name=getattr(spec, "runtime_class_name", None),
            )
            pod_resources.append(
                CloudResource(
                    arn=f"k8s://pod/{ns}/{pod_name}",
                    id=pod_name,
                    name=pod_name,
                    service="k8s",
                    kind="k8s_pod",
                    provider=CloudProvider.KUBERNETES,
                    region=ns,
                    account_id=self.kube_context or "default",
                    tags=labels,
                    is_ai_workload=True,
                    ai_reason="gpu pod or ai label",
                    metadata=attrs.model_dump(),
                )
            )

        node_resources: list[CloudResource] = []
        for node in nodes:
            meta = getattr(node, "metadata", None)
            status = getattr(node, "status", None)
            node_name = str(getattr(meta, "name", "unknown"))
            labels = dict(getattr(meta, "labels", None) or {})
            cap = dict(
                getattr(status, "capacity", None) or getattr(status, "allocatable", None) or {}
            )
            try:
                gpu_cap = int(cap.get("nvidia.com/gpu", 0))
            except (ValueError, TypeError):
                gpu_cap = 0
            if gpu_cap <= 0:
                continue

            tk_label_ver = (
                labels.get("nvidia.com/container-toolkit.version") or operator_toolkit_ver
            )
            n_attrs = K8sNodeAttrs(
                gpu_capacity=gpu_cap,
                gpu_product=labels.get("nvidia.com/gpu.product"),
                mig_config=labels.get("nvidia.com/mig.config"),
                toolkit_version=str(tk_label_ver) if tk_label_ver else None,
                multi_tenant_gpu_namespaces=len(node_gpu_namespaces.get(node_name, set())),
            )
            node_resources.append(
                CloudResource(
                    arn=f"k8s://node/{node_name}",
                    id=node_name,
                    name=node_name,
                    service="k8s",
                    kind="k8s_node",
                    provider=CloudProvider.KUBERNETES,
                    region="cluster",
                    account_id=self.kube_context or "default",
                    tags=labels,
                    is_ai_workload=True,
                    ai_reason=f"nvidia.com/gpu={gpu_cap}",
                    metadata=n_attrs.model_dump(),
                )
            )

        return node_resources + pod_resources
