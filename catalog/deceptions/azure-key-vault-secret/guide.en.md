## Story

A secret in a key vault of your subscription that holds a random value. An intruder who has taken over an identity that may read the vault lists the secrets, finds one with a name like `orders-db-password` and reads it. The vault writes the read to its audit log, an alert rule finds it there, and an action group forwards the alert to the URL of a honeytoken with a `POST`. The alert says that the secret was read.

## Setup

The commands are for a shell such as bash or zsh, with the Azure CLI, signed in to the subscription of the vault. They were checked against the documentation of the Azure CLI, Azure Monitor and Key Vault, not run against a subscription. The Azure CLI may offer to install an extension when a command needs one.

### What the bait does in the subscription

- The secret holds a random value of about 30 characters that you generate and keep nowhere. It belongs to nothing: reading it opens nothing.
- The vault is one that exists. The decoy stands among its real secrets, which is why an existing vault serves better than a new one that nobody uses. The commands change nothing about its access rules.
- Everything that the vault logs goes to a Log Analytics workspace, not only this secret. That costs ingestion in proportion to the traffic of the vault, and the alert rule costs by how often it is evaluated; see the pricing pages of Azure Monitor. Choose a vault with little traffic, or one that already logs to a workspace.
- Everything of yours that reads all the secrets of the vault, such as a backup or a scanner, also reads this one and raises the alert.

### What it needs

1. **An account** that may set secrets in the vault (for example with the role Key Vault Secrets Officer), create resources in the resource group of the vault and create alert rules (for example with the role Monitoring Contributor), or that is owner of the resource group.
2. **The URL of the URL honeytoken "Webhook of the action group"**, `Honeytoken-URL`. It stands in the action group in your subscription. Treat it as a secret: whoever knows it can send forged events, and whoever may read the action group can find it.
3. **Names that Azure accepts.** The name of the secret may contain only letters, digits and hyphens. A command fails halfway if a name does not fit, so keep the names that you change short (a workspace name has up to 63 characters).

### Step 1: variables and the secret

```bash
LOCATION=germanywestcentral
VAULT=kv-orders-prod
SUB=$(az account show --query id --output tsv)
RG=$(az keyvault show --name "$VAULT" --query resourceGroup --output tsv)
VAULT_ID=$(az keyvault show --name "$VAULT" --query id --output tsv)
az keyvault secret set --vault-name "$VAULT" --name orders-db-password --value "$(openssl rand -base64 24 | tr -d '/+=')" --query id --output tsv
```

The `--query` keeps the value out of the output. The value stands on the command line while the command runs, so that other users of the same computer can see it for a moment; for a value that opens nothing, that is acceptable. Choose a name for the secret that fits the way your teams name secrets.

### Step 2: log the vault to a workspace

If the vault already sends its audit log (`AuditEvent`) to a Log Analytics workspace, `az monitor diagnostic-settings list --resource "$VAULT_ID"` shows it. Then use that workspace in the next steps: set `WS_ID` to its resource ID and `LOCATION` to its region with `LOCATION=$(az monitor log-analytics workspace show --ids "$WS_ID" --query location --output tsv)`, because the alert rule must be in the region of the workspace. Read the note on tables below. Otherwise create one:

```bash
az monitor log-analytics workspace create --resource-group "$RG" --workspace-name audit-notify-vault-logs --location "$LOCATION"
WS_ID=$(az monitor log-analytics workspace show --resource-group "$RG" --workspace-name audit-notify-vault-logs --query id --output tsv)
az monitor diagnostic-settings create --name audit-notify-vault-diag --resource "$VAULT_ID" --workspace "$WS_ID" --logs '[{"category":"AuditEvent","enabled":true}]'
```

The query in step 4 reads the table `AzureDiagnostics`, which is where the logs of a vault go by default. If the existing setting writes to the table `AZKVAuditLogs` instead (the dedicated destination), change the query and the dimensions as the table reference of Azure Monitor lists the columns: `AZKVAuditLogs` instead of `AzureDiagnostics` and no condition on `ResourceProvider`, `RequestUri` for `requestUri_s`, `CallerIpAddress` for `CallerIPAddress`, `ResultType` for `ResultSignature`, and no dimension `clientInfo_s`, whose content is in the column `Properties`.

### Step 3: action group

The action group sends the alert to the honeytoken. The common alert schema is the only format that the alert rule of step 4 supports.

```bash
az monitor action-group create --resource-group "$RG" --name audit-notify-vault-ag --short-name notify --action webhook notify 'Honeytoken-URL' usecommonalertschema
AG_ID=$(az monitor action-group show --resource-group "$RG" --name audit-notify-vault-ag --query id --output tsv)
```

### Step 4: alert rule

The rule looks every five minutes at the last ten for reads of this secret. It splits the alert by the address of the caller, the client and the result, so that these three values appear in the body of the request, in the list `dimensions`. The command `az monitor scheduled-query create` cannot split by dimensions, so the rule goes through the REST API of Azure Monitor with `az rest`. The query is not validated, because the columns of the table `AzureDiagnostics` exist only after the first log has arrived.

```bash
cat > rule.json <<EOF
{"location":"$LOCATION","properties":{"severity":1,"enabled":true,"evaluationFrequency":"PT5M","windowSize":"PT10M","scopes":["$WS_ID"],"criteria":{"allOf":[{"query":"AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and OperationName == 'SecretGet' and _ResourceId =~ '$VAULT_ID' and (requestUri_s contains '/secrets/orders-db-password/' or requestUri_s contains '/secrets/orders-db-password?')","timeAggregation":"Count","dimensions":[{"name":"CallerIPAddress","operator":"Include","values":["*"]},{"name":"clientInfo_s","operator":"Include","values":["*"]},{"name":"ResultSignature","operator":"Include","values":["*"]}],"operator":"GreaterThan","threshold":0,"failingPeriods":{"numberOfEvaluationPeriods":1,"minFailingPeriodsToAlert":1}}]},"actions":{"actionGroups":["$AG_ID"]},"skipQueryValidation":true}}
EOF
az rest --method put --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/scheduledQueryRules/audit-notify-vault-rule?api-version=2021-08-01" --body @rule.json
rm rule.json
```

### Placing the bait

The secret is found by listing the secrets of the vault, so it needs no file. To make it found sooner, mention its name where the people of the story would: in the readme of a repository, in a deployment configuration (`orders-db-password` as the name of the secret to load) or in a ticket. Record where you did it in the scenario.

## Testing

With your own account, read the secret:

```bash
az keyvault secret show --vault-name "$VAULT" --name orders-db-password --query id --output tsv
```

The audit log reaches the workspace after some minutes, and the rule looks at it every five minutes. Azure Monitor gives no guarantee for the delay, so allow a quarter of an hour, the first time perhaps more. Then the scenario shows an incident. Look at the body of its event: after the fields of the alert it holds the list `dimensions` with the address, the client and the result:

```json
{"name":"CallerIPAddress","value":"203.0.113.10"},{"name":"clientInfo_s","value":"azsdk-python-keyvault-secrets/4.x ..."},{"name":"ResultSignature","value":"OK"}
```

If the body ends before `dimensions`, it was cut at 4096 bytes: the names of the subscription, resource group and rule before it are too long. Use a shorter name for the resource group of the forwarding resources, shorten the names of the forwarding resources in the commands, and repeat the test. Close the incident after the test.

## Removing

```bash
az rest --method delete --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/scheduledQueryRules/audit-notify-vault-rule?api-version=2021-08-01"
az monitor action-group delete --resource-group "$RG" --name audit-notify-vault-ag
az monitor diagnostic-settings delete --name audit-notify-vault-diag --resource "$VAULT_ID"
az monitor log-analytics workspace delete --resource-group "$RG" --workspace-name audit-notify-vault-logs --yes
az keyvault secret delete --vault-name "$VAULT" --name orders-db-password
```

Skip the third and fourth command if you used a workspace that existed before. A deleted secret stays in the vault in a deleted state until its retention ends or someone purges it.

## Limits

- **Only reads that the vault logs.** A vault whose audit log is not sent to the workspace, or whose setting someone removes, reports nothing, and the alert ends without a sign.
- **Delay.** Minutes. The log needs time to arrive, and the rule runs every five minutes over a window of ten.
- **Repetition.** Azure Monitor treats an alert as one until its condition has cleared. A second read from the same address, client and result in a short time may not be reported again, and a read that falls into two windows may be reported twice. The honeytoken answers every request alike.
- **The alert names the honeytoken, not the caller.** The address of the event is that of the Azure service that sends the webhook. The caller, its address and its client are only in the start of the body, which the console shows as text of an attacker and which appears in no alert.
- **The identity is not in the body.** The list holds the address, the client and the result. Who signed in is in the audit log of the vault, in your workspace, at the time of the alert.
- **What is matched.** Reading the value of the secret by its name. Listing the secrets raises nothing.
- **Your own tools.** Anything of yours that reads the secret, including you, raises the alert.
- **Visible to those who look.** An intruder with read access to the action group sees the URL.
