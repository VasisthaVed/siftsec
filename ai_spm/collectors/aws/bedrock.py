"""Amazon Bedrock & Bedrock Agent collector (Phase 2.6)."""

from typing import Any, ClassVar, Literal

from ai_spm.collectors.aws.base import AWSBaseCollector, ResourceGoneError
from ai_spm.engine.attrs import (
    BedrockAccountConfigAttrs,
    BedrockAgentAttrs,
    BedrockDataSourceAttrs,
    BedrockGuardrailAttrs,
)
from ai_spm.engine.models import CloudProvider, CloudResource
from ai_spm.utils.aws_arn import build_arn


class BedrockCollector(AWSBaseCollector):
    """Collects Bedrock logging config, guardrails, agents, and knowledge base data sources."""

    service: ClassVar[str] = "bedrock"
    scope: ClassVar[Literal["regional", "global"]] = "regional"
    required_actions: ClassVar[tuple[str, ...]] = (
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:ListGuardrails",
        "bedrock:GetGuardrail",
        "bedrock:ListAgents",
        "bedrock:GetAgent",
        "bedrock:ListKnowledgeBases",
        "bedrock:GetKnowledgeBase",
        "bedrock:ListDataSources",
        "bedrock:GetDataSource",
        "bedrock:ListTagsForResource",
    )

    def collect_region(self, region: str | None) -> list[CloudResource]:
        target_region = region or "us-east-1"
        bedrock = self.factory.client("bedrock", region=target_region)
        agent_client = self.factory.client("bedrock-agent", region=target_region)

        out: list[CloudResource] = []
        guardrails = self._collect_guardrails(bedrock, target_region)
        agents = self._collect_agents(agent_client, target_region)
        data_sources = self._collect_knowledge_bases(agent_client, target_region)
        bedrock_in_use = bool(guardrails or agents or data_sources)

        out.append(self._collect_account_logging(bedrock, target_region, bedrock_in_use))
        out.extend(guardrails)
        out.extend(agents)
        out.extend(data_sources)
        return out

    def _collect_account_logging(
        self, bedrock: Any, region: str, bedrock_in_use: bool
    ) -> CloudResource:
        gaps: dict[str, str] = {}
        resp = self.call(gaps, "logging", bedrock.get_model_invocation_logging_configuration)
        cw_on = False
        s3_on = False
        if isinstance(resp, dict):
            cfg = resp.get("loggingConfig") or {}
            cw_on = bool(cfg.get("cloudWatchConfig", {}).get("logGroupName"))
            s3_on = bool(cfg.get("s3Config", {}).get("bucketName"))

        attrs = BedrockAccountConfigAttrs(
            logging_enabled=cw_on or s3_on,
            cloudwatch_enabled=cw_on,
            s3_enabled=s3_on,
            bedrock_in_use=bedrock_in_use,
        )
        arn = build_arn(
            self.identity.partition, "bedrock", region, self.identity.account_id, "logging-config"
        )
        return CloudResource(
            arn=arn,
            id=f"bedrock-logging-{region}",
            name=f"bedrock-logging-{region}",
            service="bedrock",
            kind="bedrock_account_config",
            provider=CloudProvider.AWS,
            region=region,
            account_id=self.identity.account_id,
            gaps=gaps,
            is_ai_workload=True,
            ai_reason="service bedrock is AI by nature",
            metadata=attrs.model_dump(),
        )

    def _collect_guardrails(self, bedrock: Any, region: str) -> list[CloudResource]:
        out: list[CloudResource] = []
        resp = self.call({}, "guardrails", bedrock.list_guardrails)
        if not isinstance(resp, dict):
            return out

        for gr in resp.get("guardrails", []):
            gr_id = str(gr["id"])
            arn = str(gr["arn"])
            name = str(gr.get("name", gr_id))
            gaps: dict[str, str] = {}
            try:
                desc = self.call(gaps, "describe", bedrock.get_guardrail, guardrailIdentifier=gr_id)
                attrs = BedrockGuardrailAttrs(
                    guardrail_id=gr_id,
                    status=desc.get("status") if isinstance(desc, dict) else gr.get("status"),
                    kms_key_arn=desc.get("kmsKeyArn") if isinstance(desc, dict) else None,
                )
                out.append(
                    CloudResource(
                        arn=arn,
                        id=gr_id,
                        name=name,
                        service="bedrock",
                        kind="bedrock_guardrail",
                        provider=CloudProvider.AWS,
                        region=region,
                        account_id=self.identity.account_id,
                        gaps=gaps,
                        is_ai_workload=True,
                        ai_reason="service bedrock is AI by nature",
                        metadata=attrs.model_dump(),
                    )
                )
            except ResourceGoneError:
                continue
        return out

    def _collect_agents(self, agent_client: Any, region: str) -> list[CloudResource]:
        out: list[CloudResource] = []
        resp = self.call({}, "agents", agent_client.list_agents)
        if not isinstance(resp, dict):
            return out

        for ag in resp.get("agentSummaries", []):
            ag_id = str(ag["agentId"])
            name = str(ag.get("agentName", ag_id))
            gaps: dict[str, str] = {}
            try:
                desc = self.call(gaps, "describe", agent_client.get_agent, agentId=ag_id)
                agent = desc.get("agent", {}) if isinstance(desc, dict) else {}
                gr_cfg = agent.get("guardrailConfiguration", {}) or {}
                arn = str(
                    agent.get(
                        "agentArn",
                        build_arn(
                            self.identity.partition,
                            "bedrock",
                            region,
                            self.identity.account_id,
                            f"agent/{ag_id}",
                        ),
                    )
                )
                attrs = BedrockAgentAttrs(
                    agent_status=agent.get("agentStatus"),
                    role_arn=agent.get("agentResourceRoleArn"),
                    guardrail_id=gr_cfg.get("guardrailIdentifier"),
                    guardrail_version=gr_cfg.get("guardrailVersion"),
                    customer_encryption_key_arn=agent.get("customerEncryptionKeyArn"),
                )
                meta = attrs.model_dump()
                out.append(
                    CloudResource(
                        arn=arn,
                        id=ag_id,
                        name=name,
                        service="bedrock",
                        kind="bedrock_agent",
                        provider=CloudProvider.AWS,
                        region=region,
                        account_id=self.identity.account_id,
                        gaps=gaps,
                        is_ai_workload=True,
                        ai_reason="service bedrock is AI by nature",
                        metadata=meta,
                    )
                )
            except ResourceGoneError:
                continue
        return out

    def _collect_knowledge_bases(self, agent_client: Any, region: str) -> list[CloudResource]:
        out: list[CloudResource] = []
        kb_resp = self.call({}, "knowledge_bases", agent_client.list_knowledge_bases)
        if not isinstance(kb_resp, dict):
            return out

        for kb in kb_resp.get("knowledgeBaseSummaries", []):
            kb_id = str(kb["knowledgeBaseId"])
            kb_desc = self.call(
                {}, "kb_describe", agent_client.get_knowledge_base, knowledgeBaseId=kb_id
            )
            vector_arn: str | None = None
            if isinstance(kb_desc, dict):
                storage = kb_desc.get("knowledgeBase", {}).get("storageConfiguration", {})
                os_cfg = storage.get("opensearchServerlessConfiguration", {})
                vector_arn = os_cfg.get("collectionArn")

            ds_resp = self.call(
                {}, "data_sources", agent_client.list_data_sources, knowledgeBaseId=kb_id
            )
            if not isinstance(ds_resp, dict):
                continue

            for ds in ds_resp.get("dataSourceSummaries", []):
                ds_id = str(ds["dataSourceId"])
                ds_name = str(ds.get("name", ds_id))
                gaps: dict[str, str] = {}
                try:
                    desc = self.call(
                        gaps,
                        "describe",
                        agent_client.get_data_source,
                        knowledgeBaseId=kb_id,
                        dataSourceId=ds_id,
                    )
                    ds_obj = desc.get("dataSource", {}) if isinstance(desc, dict) else {}
                    sse = ds_obj.get("serverSideEncryptionConfiguration", {}) or {}
                    arn = build_arn(
                        self.identity.partition,
                        "bedrock",
                        region,
                        self.identity.account_id,
                        f"knowledge-base/{kb_id}/data-source/{ds_id}",
                    )
                    attrs = BedrockDataSourceAttrs(
                        knowledge_base_id=kb_id,
                        vector_store_arn=vector_arn,
                        kms_key_arn=sse.get("kmsKeyArn"),
                    )
                    out.append(
                        CloudResource(
                            arn=arn,
                            id=ds_id,
                            name=ds_name,
                            service="bedrock",
                            kind="bedrock_data_source",
                            provider=CloudProvider.AWS,
                            region=region,
                            account_id=self.identity.account_id,
                            gaps=gaps,
                            is_ai_workload=True,
                            ai_reason="service bedrock is AI by nature",
                            metadata=attrs.model_dump(),
                        )
                    )
                except ResourceGoneError:
                    continue
        return out
