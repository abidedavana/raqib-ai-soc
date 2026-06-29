# Wazuh SIEM integration

Raqib forwards every security event to **Wazuh**, so attacks against the AI become
native SIEM alerts — the "LLM threat detection feeds centralized SOC monitoring"
best practice, made real. Raqib writes JSON events; a custom Wazuh ruleset
([`rules/raqib_rules.xml`](rules/raqib_rules.xml)) maps them to alert levels and
ATT&CK/ATLAS-tagged groups.

```
Raqib gateway ──JSON log──▶ wazuh/logs/raqib-events.json
                                   │ (bind-mounted into the manager)
                                   ▼
        Wazuh manager (json localfile) ──▶ raqib_rules.xml ──▶ Wazuh alerts
                                   ▼
                          Wazuh dashboard (filter: rule.groups = raqib)
```

> ### Read this first — honesty + resources
> Wazuh's stack (manager + indexer + dashboard) is the **one genuinely heavy,
> finicky part** of this project: it needs Docker, ~**4 GB RAM**, a kernel tweak,
> and TLS cert generation. Treat the first bring-up as **iterative** — exactly how
> a real SIEM deployment goes. The high-value, reusable artifacts (the custom
> rules and the forwarder) are done and tested; this guide stands the SIEM up
> around them. Close other heavy apps before you start.

---

## Step 1 — Install WSL2 + Docker Desktop  ⚠️ requires admin + a reboot

```powershell
# In an ADMIN PowerShell:
wsl --install
# -> reboot when prompted
```
Then install **Docker Desktop for Windows** from https://www.docker.com/products/docker-desktop/
(use the WSL2 backend, the default). Launch it once and wait until it says
"Engine running". Verify:
```powershell
docker --version
docker compose version
```

## Step 2 — Raise vm.max_map_count (the indexer needs it)

```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```
> This resets when Docker restarts. To make it permanent, add `vm.max_map_count=262144`
> to a `[wsl2]` … `kernelCommandLine` entry in `%USERPROFILE%\.wslconfig` (we can
> do this together).

## Step 3 — Deploy the Wazuh single-node stack

We deploy the **official** Wazuh single-node stack (don't reinvent it) and layer
Raqib on top.

```powershell
# pick the current stable tag from https://github.com/wazuh/wazuh-docker/releases
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
cd wazuh-docker/single-node

# generate TLS certs (one-time)
docker compose -f generate-indexer-certs.yml run --rm generator
```

**Low-RAM tuning (recommended on 16 GB):** in `single-node/docker-compose.yml`,
set the indexer heap small — under `wazuh.indexer` → `environment`:
```yaml
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
```

## Step 4 — Apply the Raqib overlay

In `single-node/docker-compose.yml`, under **`wazuh.manager` → `volumes:`**, add
(adjust the path if your repo lives elsewhere):
```yaml
      - C:/Users/abide/Downloads/CYber/wazuh/logs:/var/log/raqib
      - C:/Users/abide/Downloads/CYber/wazuh/rules/raqib_rules.xml:/var/ossec/etc/rules/raqib_rules.xml
```
Then add the **localfile** block from [`config/raqib-localfile.xml`](config/raqib-localfile.xml)
inside `<ossec_config>` in `single-node/config/wazuh_cluster/wazuh_manager.conf`
(just before `</ossec_config>`).

Bring it up:
```powershell
docker compose up -d
```
- Dashboard: **https://localhost:443**  (default `admin` / `SecretPassword` — change it)

## Step 5 — Point Raqib at Wazuh

In `gateway/.env`:
```
WAZUH_ENABLED=true
WAZUH_MODE=file
WAZUH_LOG_FILE=../wazuh/logs/raqib-events.json
```
Restart the gateway.

## Step 6 — Generate attacks and watch alerts land

```powershell
# gateway running, then:
python redteam/run_harness.py --target http://localhost:8000
```
In the Wazuh dashboard → **Threat Hunting / Events**, filter `rule.groups: raqib`.
You should see Raqib alerts: criticals (rule 100610/100620/100621), highs (100611),
blocked attacks (100630), each carrying the OWASP/ATLAS tag in the description.

---

## Verify / troubleshoot
| Symptom | Check |
|---------|-------|
| No `raqib-events.json` file | Is `WAZUH_ENABLED=true` and `WAZUH_MODE=file`? Did the gateway handle a request? |
| File has lines but no alerts | Is the bind-mount path correct? `docker exec <manager> tail /var/log/raqib/raqib-events.json` |
| Rules not loading | `docker exec <manager> /var/ossec/bin/wazuh-logtest` and paste a JSON line to test |
| Indexer won't start | `vm.max_map_count` (Step 2) and free RAM |

## Screenshot for the portfolio
Once alerts are flowing, capture the Wazuh dashboard filtered to `rule.groups: raqib`
and save it as `../docs/screenshots/wazuh-alerts.png`. That image — AI attacks as
SIEM alerts — is the proof of "real SOC integration" that hiring managers love.

> We'll run Steps 1–6 together and fix anything version-specific as it comes up —
> SIEM deployments always need a little live tuning.
