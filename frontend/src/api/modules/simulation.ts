export type SimulationProtocol =
  | "http"
  | "redis"
  | "smtp"
  | "pop3"
  | "imap"
  | "ssh"
  | "ftp"
  | "rdp";

export const SIMULATION_PROTOCOL_OPTIONS: {
  value: SimulationProtocol;
  label: string;
}[] = [
  { value: "http", label: "HTTP" },
  { value: "redis", label: "Redis" },
  { value: "smtp", label: "SMTP" },
  { value: "pop3", label: "POP3" },
  { value: "imap", label: "IMAP" },
  { value: "ssh", label: "SSH" },
  { value: "ftp", label: "FTP" },
  { value: "rdp", label: "RDP" },
];

export const SIMULATION_PROTOCOL_DEFAULT_PORTS: Record<
  SimulationProtocol,
  number
> = {
  http: 8080,
  redis: 6379,
  smtp: 25,
  pop3: 110,
  imap: 143,
  ssh: 22,
  ftp: 21,
  rdp: 3389,
};

export interface SimulationProtocolCapability {
  protocol: SimulationProtocol;
  label: string;
  defaultPort: number;
  deployable: boolean;
  customRuleCreatable: boolean;
  eventTypes: string[];
}

export interface SimRule {
  id: number;
  name: string;
  nameEn: string;
  cve?: string;
  category: string;
  descriptionZh: string;
  descriptionEn: string;
  protocol: string;
  defaultPort?: number;
  configYaml: string;
  createdAt: string;
  updatedAt: string;
}

export interface SimInstance {
  instanceId: string;
  nodeId: string;
  ruleId: number;
  ruleName: string;
  protocol: string;
  listenPort: number;
  status: "active" | "inactive" | "error";
  errorMessage?: string;
  pcapStatus: "idle" | "capturing" | "ready";
  pcapStartTime?: number;
  pcapFilePath?: string;
  createdAt: string;
  updatedAt: string;
}

export interface SimLog {
  logId?: number;
  instanceId: string;
  nodeId: string;
  clientIp: string;
  clientPort: number;
  eventType: string;
  detailSummary: string;
  payloadHex?: string;
  pcapFilePath?: string;
  timestamp: string;
}

export interface SimRulePackage {
  packageId: string;
  version: string;
  rulesetFormatVersion: number;
  minSeclabVersion: string;
  ruleCount: number;
  signatureHex: string;
  archiveSha256: string;
  status: "active" | "superseded";
  importedAt: string;
}

export interface CreateRuleReq {
  name: string;
  nameEn?: string;
  cve?: string;
  category?: string;
  descriptionZh?: string;
  descriptionEn?: string;
  protocol: string;
  defaultPort?: number;
  configYaml: string;
}

export interface DeploySimReq {
  nodeId: string;
  port: number;
  ruleId: number;
  seclabCallbackUrl: string;
}

type ApiEnvelope<T> = {
  success: boolean;
  data?: T;
  message?: string;
  messageKey?: string;
};

type SuitePackage = Omit<
  SimRulePackage,
  "signatureHex" | "archiveSha256" | "status"
>;

type SuiteRule = {
  id: string;
  name: string;
  protocol: string;
  defaultPort: number;
  configJson: string;
  createdAt: string;
  updatedAt: string;
};

type SuiteInstance = {
  id: string;
  ruleId: string;
  ruleName: string;
  protocol: string;
  hostPort: number;
  status: string;
  errorMessage?: string | null;
  pcapStatus?: "idle" | "capturing" | "ready";
  pcapStartTime?: number | null;
  pcapFilePath?: string | null;
  createdAt: string;
  updatedAt: string;
};

type SuiteLog = {
  id: number;
  instanceId: string;
  eventType: string;
  summary: string;
  clientIp: string;
  clientPort: number;
  payloadHex?: string | null;
  pcapFilePath?: string | null;
  timestamp: string;
};

const ruleIdToBackend = new Map<number, string>();
const backendRuleIdToUi = new Map<string, number>();

async function request<T>(
  url: string,
  init?: RequestInit,
): Promise<ApiEnvelope<T>> {
  const res = await fetch(url, init);
  const body = (await res.json().catch(() => ({}))) as ApiEnvelope<T>;
  if (!res.ok || body.success === false) {
    return {
      success: false,
      message: body.message || `HTTP ${res.status}`,
      messageKey: body.messageKey,
    };
  }
  return body;
}

function apiUrl(path: string) {
  return path.replace(/^\/+/, "");
}

function uiRuleId(id: string) {
  const matched = id.match(/(\d+)$/);
  if (matched) return Number(matched[1]);
  let hash = 0;
  for (const ch of id) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return 1_000_000 + (hash % 900_000_000);
}

function rememberRuleId(backendId: string) {
  const id = uiRuleId(backendId);
  backendRuleIdToUi.set(backendId, id);
  ruleIdToBackend.set(id, backendId);
  return id;
}

function parseConfig(rule: SuiteRule) {
  try {
    const raw = JSON.parse(rule.configJson) as Record<string, unknown>;
    const behavior =
      raw.behavior && typeof raw.behavior === "object" ? raw.behavior : raw;
    return {
      nameEn: typeof raw.nameEn === "string" ? raw.nameEn : undefined,
      cve: typeof raw.cve === "string" ? raw.cve : undefined,
      category: typeof raw.category === "string" ? raw.category : "custom",
      descriptionZh: typeof raw.description === "string" ? raw.description : "",
      descriptionEn:
        typeof raw.descriptionEn === "string" ? raw.descriptionEn : "",
      configYaml: JSON.stringify(behavior, null, 2),
    };
  } catch {
    return {
      nameEn: undefined,
      cve: undefined,
      category: "custom",
      descriptionZh: "",
      descriptionEn: "",
      configYaml: "{}",
    };
  }
}

function mapRule(rule: SuiteRule): SimRule {
  const parsed = parseConfig(rule);
  return {
    id: rememberRuleId(rule.id),
    name: rule.name,
    nameEn: parsed.nameEn || rule.name,
    cve: parsed.cve,
    category: parsed.category,
    descriptionZh: parsed.descriptionZh,
    descriptionEn: parsed.descriptionEn,
    protocol: rule.protocol,
    defaultPort: rule.defaultPort,
    configYaml: parsed.configYaml,
    createdAt: rule.createdAt,
    updatedAt: rule.updatedAt,
  };
}

function mapInstance(instance: SuiteInstance): SimInstance {
  return {
    instanceId: instance.id,
    nodeId: "local",
    ruleId: rememberRuleId(instance.ruleId),
    ruleName: instance.ruleName,
    protocol: instance.protocol,
    listenPort: instance.hostPort,
    status:
      instance.status === "running" || instance.status === "deploying"
        ? "active"
        : instance.status === "error"
          ? "error"
          : "inactive",
    errorMessage: instance.errorMessage || undefined,
    pcapStatus: instance.pcapStatus ?? "idle",
    pcapStartTime: instance.pcapStartTime ?? undefined,
    pcapFilePath: instance.pcapFilePath ?? undefined,
    createdAt: instance.createdAt,
    updatedAt: instance.updatedAt,
  };
}

function mapLog(log: SuiteLog): SimLog {
  return {
    logId: log.id,
    instanceId: log.instanceId,
    nodeId: "local",
    clientIp: log.clientIp,
    clientPort: log.clientPort,
    eventType: log.eventType,
    detailSummary: log.summary,
    payloadHex: log.payloadHex || undefined,
    pcapFilePath: log.pcapFilePath || undefined,
    timestamp: log.timestamp,
  };
}

function fail<T>(res: ApiEnvelope<unknown>): ApiEnvelope<T> {
  return { success: false, message: res.message, messageKey: res.messageKey };
}

function mapPackage(pkg: SuitePackage): SimRulePackage {
  return {
    ...pkg,
    signatureHex: "",
    archiveSha256: "",
    status: "active",
  };
}

export const simulationApi = {
  async listProtocols(): Promise<ApiEnvelope<SimulationProtocolCapability[]>> {
    return {
      success: true,
      data: SIMULATION_PROTOCOL_OPTIONS.map((item) => ({
        protocol: item.value,
        label: item.label,
        defaultPort: SIMULATION_PROTOCOL_DEFAULT_PORTS[item.value],
        deployable: true,
        customRuleCreatable: true,
        eventTypes: [],
      })),
    } satisfies ApiEnvelope<SimulationProtocolCapability[]>;
  },
  async createRule(data: CreateRuleReq): Promise<ApiEnvelope<SimRule>> {
    const res = await request<SuiteRule>(apiUrl("/api/rules"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: data.name,
        protocol: data.protocol,
        defaultPort: data.defaultPort,
        configJson: JSON.parse(data.configYaml || "{}"),
      }),
    });
    return res.success && res.data
      ? { success: true, data: mapRule(res.data) }
      : fail<SimRule>(res);
  },
  async listRules(): Promise<ApiEnvelope<SimRule[]>> {
    const res = await request<SuiteRule[]>(apiUrl("/api/rules"));
    return res.success && res.data
      ? { success: true, data: res.data.map(mapRule) }
      : fail<SimRule[]>(res);
  },
  async deleteRule(id: number) {
    const backendId = ruleIdToBackend.get(id) || String(id);
    return request<unknown>(
      apiUrl(`/api/rules/${encodeURIComponent(backendId)}`),
      {
        method: "DELETE",
      },
    );
  },
  async importRulePackage(file: File): Promise<ApiEnvelope<SimRulePackage>> {
    const formData = new FormData();
    formData.append("archive", file);
    const res = await request<SuitePackage>(
      apiUrl("/api/rule-package/import"),
      {
        method: "POST",
        body: formData,
      },
    );
    return res.success && res.data
      ? { success: true, data: mapPackage(res.data) }
      : fail<SimRulePackage>(res);
  },
  async listRulePackages(): Promise<ApiEnvelope<SimRulePackage[]>> {
    const res = await this.getCurrentRulePackage();
    return { success: true, data: res.data ? [res.data] : [] };
  },
  async getCurrentRulePackage(): Promise<ApiEnvelope<SimRulePackage | null>> {
    const res = await request<SuitePackage | null>(
      apiUrl("/api/rule-package/current"),
    );
    return res.success
      ? { success: true, data: res.data ? mapPackage(res.data) : null }
      : fail<SimRulePackage | null>(res);
  },
  async deploySimulation(
    data: DeploySimReq,
  ): Promise<ApiEnvelope<SimInstance>> {
    const backendRuleId =
      ruleIdToBackend.get(data.ruleId) || String(data.ruleId);
    const res = await request<SuiteInstance>(apiUrl("/api/instances/deploy"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ruleId: backendRuleId, hostPort: data.port }),
    });
    return res.success && res.data
      ? { success: true, data: mapInstance(res.data) }
      : fail<SimInstance>(res);
  },
  async undeploySimulation(instanceId: string) {
    return request<unknown>(
      apiUrl(`/api/instances/${encodeURIComponent(instanceId)}/undeploy`),
      {
        method: "POST",
      },
    );
  },
  async listInstances(): Promise<ApiEnvelope<SimInstance[]>> {
    const res = await request<SuiteInstance[]>(apiUrl("/api/instances"));
    return res.success && res.data
      ? {
          success: true,
          data: res.data
            .map(mapInstance)
            .filter((instance) => instance.status !== "inactive"),
        }
      : fail<SimInstance[]>(res);
  },
  async listInstanceAuditLogs(
    instanceId: string,
    params?: { page?: number; pageSize?: number },
  ): Promise<
    ApiEnvelope<{
      total: number;
      page: number;
      pageSize: number;
      records: SimLog[];
    }>
  > {
    const page = params?.page ?? 1;
    const pageSize = params?.pageSize ?? 50;
    const query = new URLSearchParams({
      page: String(page),
      pageSize: String(pageSize),
    });
    const res = await request<{
      total: number;
      page: number;
      pageSize: number;
      records: SuiteLog[];
    }>(
      apiUrl(
        `/api/instances/${encodeURIComponent(instanceId)}/audit-logs?${query.toString()}`,
      ),
    );
    return res.success && res.data
      ? {
          success: true,
          data: {
            ...res.data,
            records: res.data.records.map(mapLog),
          },
        }
      : fail(res);
  },
  async startCapture(instanceId: string): Promise<ApiEnvelope<SimInstance>> {
    const res = await request<SuiteInstance>(
      apiUrl(`/api/instances/${encodeURIComponent(instanceId)}/pcap/start`),
      {
        method: "POST",
      },
    );
    return res.success && res.data
      ? { success: true, data: mapInstance(res.data) }
      : fail<SimInstance>(res);
  },
  async stopCapture(instanceId: string): Promise<ApiEnvelope<SimInstance>> {
    const res = await request<SuiteInstance>(
      apiUrl(`/api/instances/${encodeURIComponent(instanceId)}/pcap/stop`),
      {
        method: "POST",
      },
    );
    return res.success && res.data
      ? { success: true, data: mapInstance(res.data) }
      : fail<SimInstance>(res);
  },
  async resetCapture(instanceId: string): Promise<ApiEnvelope<SimInstance>> {
    const res = await request<SuiteInstance>(
      apiUrl(`/api/instances/${encodeURIComponent(instanceId)}/pcap`),
      {
        method: "DELETE",
      },
    );
    return res.success && res.data
      ? { success: true, data: mapInstance(res.data) }
      : fail<SimInstance>(res);
  },
  async downloadPcap(instanceId: string): Promise<Blob> {
    const res = await fetch(
      apiUrl(`/api/instances/${encodeURIComponent(instanceId)}/pcap/download`),
      { method: "POST" },
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.blob();
  },
  getCallbackUrl: () => apiUrl("/internal/events"),
};
