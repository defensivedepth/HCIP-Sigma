# Playbook Field Inventory — HCIP-Sigma

Catalogue of every field name used in the playbook question queries, grouped by
logsource category, with the SO/ECS field each converts to. ECS targets are
derived by running `sigma convert` through the deployed pipeline
(`sigma_final_pipeline` + `sigma_so_pipeline` + `windows-logsources` + `ecs_windows`).

**Regenerate:** `python3 scratch/gen_field_inventory.py`

## Conventions

- Question queries use **Sigma-spec field names** (`Image`, `CommandLine`, `ImageLoaded`,
  `EventID`, `Channel`, `ParentName`, …); the pipeline maps them to ECS at convert time.
- The only bare ECS field names permitted are the **platform floor** (below) — host scoping
  and prior-detection lookup, which have no Sigma-taxonomy expression.
- `winlog.event_data.<X>` should be written as bare `<X>` (Windows EventLog attribute).

## Platform floor — ECS fields with no Sigma-spec equivalent (allowed)

| field | role |
|---|---|
| `host.name` | host-scope clause (`%hostname%`) |
| `rule.uuid` | precursor-detection meta query (prior SO detections) |
| `rule.name` | precursor-detection meta query |
| `event.module` | precursor-detection meta query (`event.module: sigma`) |
| `event.severity_label` | precursor-detection meta query |

## Fields by logsource category

### `(none)`  (1086 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `host.name`  _(floor)_ | `host.name` | 1013 | 73 |
| `event.module`  _(floor)_ | `event.module` | 1065 | 0 |
| `rule.uuid`  _(floor)_ | `rule.uuid` | 55 | 993 |
| `rule.name`  _(floor)_ | `rule.name` | 10 | 1019 |
| `event.severity_label`  _(floor)_ | `event.severity_label` | 0 | 1019 |
| `User` | `user.name` | 7 | 58 |
| `EventID` | `event.code` | 1 | 33 |
| `Channel` | `winlog.channel` | 21 | 0 |
| `Operation` | `winlog.event_data.Operation` | 0 | 18 |
| `Namespace` | `winlog.event_data.Namespace` | 0 | 3 |
| `PossibleCause` | `winlog.event_data.PossibleCause` | 0 | 2 |
| `Message` | `winlog.event_data.Message` | 0 | 1 |
| `Query` | `winlog.event_data.Query` | 0 | 1 |

### `application`  (14 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `host.name`  _(floor)_ | `host.name` | 14 | 0 |
| `Provider_Name` | `winlog.provider_name` | 2 | 10 |
| `EventID` | `event.code` | 0 | 9 |
| `Data` | `winlog.event_data.Data` | 2 | 4 |
| `Message` | `winlog.event_data.Message` | 0 | 5 |
| `Provider` | `winlog.event_data.Provider` | 1 | 2 |
| `Channel` | `winlog.channel` | 2 | 0 |
| `User` | `user.name` | 0 | 2 |
| `SourceIp` | `source.ip` | 0 | 1 |
| `param1` | `winlog.event_data.param1` | 0 | 1 |
| `param2` | `winlog.event_data.param2` | 0 | 1 |
| `source` | `winlog.event_data.source` | 1 | 0 |

### `authentication`  (2 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `LogonType` | `winlog.event_data.LogonType` | 0 | 2 |
| `User` | `user.name` | 0 | 2 |
| `host.name`  _(floor)_ | `host.name` | 2 | 0 |
| `SourceIp` | `source.ip` | 0 | 1 |
| `SourceNetworkAddress` | `winlog.event_data.SourceNetworkAddress` | 0 | 1 |

### `certificateservicesclient-lifecycle-system`  (1 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 1 | 0 |
| `Subject` | `winlog.event_data.Subject` | 0 | 1 |
| `UserData` | `winlog.event_data.UserData` | 0 | 1 |
| `host.name`  _(floor)_ | `host.name` | 1 | 0 |

### `create_stream_hash`  (21 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetFilename` | `file.path` | 8 | 21 |
| `Image` | `process.executable` | 0 | 20 |
| `host.name`  _(floor)_ | `host.name` | 19 | 0 |
| `Contents` | `winlog.event_data.Contents` | 0 | 7 |
| `Hash` | `winlog.event_data.Hash` | 0 | 7 |
| `User` | `user.name` | 0 | 4 |
| `Hashes` | `winlog.event_data.Hashes` | 0 | 3 |
| `ParentProcessGuid` | `process.parent.entity_id` | 2 | 0 |
| `ProcessGuid` | `process.entity_id` | 2 | 0 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 1 |

### `dns`  (2 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `QueryName` | `dns.question.name` | 1 | 2 |
| `host.name`  _(floor)_ | `host.name` | 2 | 0 |
| `QueryResults` | `winlog.event_data.QueryResults` | 0 | 1 |

### `dns_query`  (1 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `QueryName` | `dns.question.name` | 0 | 1 |
| `QueryType` | `winlog.event_data.QueryType` | 0 | 1 |
| `host.name`  _(floor)_ | `host.name` | 1 | 0 |

### `file_delete`  (9 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetFilename` | `file.path` | 3 | 9 |
| `Image` | `process.executable` | 2 | 7 |
| `User` | `user.name` | 0 | 8 |
| `host.name`  _(floor)_ | `host.name` | 8 | 0 |
| `ProcessGuid` | `process.entity_id` | 1 | 1 |
| `ParentProcessGuid` | `process.parent.entity_id` | 1 | 0 |

### `file_event`  (787 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetFilename` | `file.path` | 307 | 786 |
| `Image` | `process.executable` | 174 | 650 |
| `host.name`  _(floor)_ | `host.name` | 460 | 4 |
| `ProcessGuid` | `process.entity_id` | 323 | 2 |
| `ParentProcessGuid` | `process.parent.entity_id` | 319 | 0 |
| `Hashes` | `winlog.event_data.Hashes` | 0 | 109 |
| `User` | `user.name` | 0 | 108 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 6 |
| `ProcessId` | `process.pid` | 0 | 1 |

### `image_load`  (234 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `ImageLoaded` | `dll.path` | 84 | 234 |
| `Image` | `process.executable` | 141 | 103 |
| `host.name`  _(floor)_ | `host.name` | 214 | 0 |
| `Signed` | `dll.code_signature.exists` | 13 | 145 |
| `Signature` | `dll.code_signature.subject_name` | 0 | 120 |
| `ProcessGuid` | `process.entity_id` | 31 | 7 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 13 |
| `SignatureStatus` | `dll.code_signature.status` | 2 | 10 |
| `Hashes` | `dll.hash.sha256` | 0 | 4 |
| `User` | `user.name` | 0 | 3 |
| `ParentProcessGuid` | `process.parent.entity_id` | 1 | 0 |

### `network_connection`  (535 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `DestinationPort` | `destination.port` | 163 | 528 |
| `Image` | `process.executable` | 278 | 267 |
| `DestinationIp` | `destination.ip` | 50 | 493 |
| `host.name`  _(floor)_ | `host.name` | 505 | 1 |
| `DestinationHostname` | `destination.domain` | 1 | 312 |
| `Initiated` | `network.direction` | 198 | 61 |
| `User` | `user.name` | 0 | 110 |
| `ProcessGuid` | `process.entity_id` | 44 | 0 |
| `SourceIp` | `source.ip` | 0 | 33 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 3 |
| `SourcePort` | `source.port` | 0 | 2 |
| `ParentImage` | `process.parent.executable` | 1 | 0 |

### `pipe_created`  (1 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `Image` | `process.executable` | 0 | 1 |
| `PipeName` | `file.name` | 0 | 1 |
| `host.name`  _(floor)_ | `host.name` | 1 | 0 |

### `powershell`  (149 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `ScriptBlockText` | `powershell.file.script_block_text` | 1 | 149 |
| `EventID` | `event.code` | 149 | 0 |
| `Path` | `winlog.event_data.Path` | 0 | 149 |
| `ScriptBlockId` | `powershell.file.script_block_id` | 0 | 149 |
| `host.name`  _(floor)_ | `host.name` | 149 | 0 |

### `process_access`  (90 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `GrantedAccess` | `winlog.event_data.GrantedAccess` | 30 | 89 |
| `TargetImage` | `winlog.event_data.TargetImage` | 55 | 46 |
| `SourceImage` | `process.executable` | 21 | 75 |
| `host.name`  _(floor)_ | `host.name` | 84 | 0 |
| `CallTrace` | `winlog.event_data.CallTrace` | 1 | 59 |
| `User` | `user.name` | 0 | 8 |
| `SourceProcessGUID` | `winlog.event_data.SourceProcessGUID` | 2 | 4 |
| `SourceProcessGuid` | `process.entity_id` | 1 | 2 |
| `TargetFilename` | `file.path` | 1 | 1 |

### `process_creation`  (14869 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `CommandLine` | `process.command_line` | 8787 | 5746 |
| `Image` | `process.executable` | 6497 | 5817 |
| `host.name`  _(floor)_ | `host.name` | 4783 | 6074 |
| `ProcessGuid` | `process.entity_id` | 4991 | 1 |
| `User` | `user.name` | 2204 | 2784 |
| `ParentImage` | `process.parent.executable` | 1647 | 2821 |
| `OriginalFileName` | `process.pe.original_file_name` | 2587 | 860 |
| `ParentName` | `process.parent.name` | 2345 | 0 |
| `CurrentDirectory` | `process.working_directory` | 59 | 827 |
| `ParentCommandLine` | `process.parent.command_line` | 301 | 361 |
| `Description` | `process.pe.description` | 335 | 79 |
| `Hashes` | `process.hash.sha256` | 176 | 143 |
| `ParentProcessGuid` | `process.parent.entity_id` | 280 | 1 |
| `Product` | `process.pe.product` | 218 | 48 |
| `IntegrityLevel` | `process.Ext.token.integrity_level_name` | 129 | 75 |
| `Company` | `process.pe.company` | 92 | 20 |
| `LogonId` | `winlog.event_data.LogonId` | 11 | 2 |
| `ParentUser` | `winlog.event_data.ParentUser` | 11 | 2 |
| `FileVersion` | `process.pe.file_version` | 9 | 2 |
| `Provider_Name` | `winlog.provider_name` | 3 | 0 |
| `Signed` | `file.code_signature.signed` | 0 | 2 |
| `EventID` | `event.code` | 1 | 0 |
| `NewProcessName` | `process.executable` | 0 | 1 |
| `Signature` | `winlog.event_data.Signature` | 0 | 1 |
| `SignatureStatus` | `file.code_signature.status` | 0 | 1 |
| `SubjectUserName` | `winlog.event_data.SubjectUserName` | 0 | 1 |
| `TokenElevationType` | `winlog.event_data.TokenElevationType` | 0 | 1 |

### `registry_set`  (192 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetObject` | `registry.path` | 148 | 192 |
| `Details` | `registry.data.strings` | 1 | 173 |
| `Image` | `process.executable` | 0 | 134 |
| `host.name`  _(floor)_ | `host.name` | 134 | 0 |
| `ProcessGuid` | `process.entity_id` | 58 | 1 |
| `User` | `user.name` | 0 | 25 |
| `EventType` | `event.action` | 1 | 0 |

### `security`  (136 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 127 | 49 |
| `host.name`  _(floor)_ | `host.name` | 107 | 18 |
| `SubjectUserName` | `user.name` | 3 | 77 |
| `TargetUserName` | `winlog.event_data.TargetUserName` | 12 | 51 |
| `LogonType` | `winlog.event_data.LogonType` | 6 | 46 |
| `IpAddress` | `source.ip` | 0 | 51 |
| `ObjectName` | `winlog.event_data.ObjectName` | 3 | 16 |
| `TaskName` | `winlog.event_data.TaskName` | 0 | 17 |
| `ServiceName` | `service.name` | 0 | 16 |
| `AccessMask` | `winlog.event_data.AccessMask` | 0 | 13 |
| `PrivilegeList` | `winlog.event_data.PrivilegeList` | 0 | 12 |
| `ProcessName` | `process.executable` | 0 | 10 |
| `TaskContent` | `winlog.event_data.TaskContent` | 0 | 10 |
| `RelativeTargetName` | `winlog.event_data.RelativeTargetName` | 4 | 5 |
| `ServiceFileName` | `winlog.event_data.ServiceFileName` | 0 | 9 |
| `ShareName` | `winlog.event_data.ShareName` | 4 | 4 |
| `TicketEncryptionType` | `winlog.event_data.TicketEncryptionType` | 3 | 3 |
| `ServiceAccount` | `winlog.event_data.ServiceAccount` | 0 | 5 |
| `User` | `user.name` | 0 | 5 |
| `ServiceType` | `winlog.event_data.ServiceType` | 0 | 4 |
| `Computer` | `winlog.event_data.Computer` | 3 | 0 |
| `ObjectType` | `winlog.event_data.ObjectType` | 0 | 3 |
| `AuditPolicyChanges` | `winlog.event_data.AuditPolicyChanges` | 0 | 2 |
| `MemberName` | `winlog.event_data.MemberName` | 0 | 2 |
| `ObjectDN` | `winlog.event_data.ObjectDN` | 1 | 1 |
| `Properties` | `winlog.event_data.Properties` | 1 | 1 |
| `SubjectDomainName` | `user.domain` | 0 | 2 |
| `SubjectLogonId` | `winlog.logon.id` | 0 | 2 |
| `WorkstationName` | `source.domain` | 0 | 2 |
| `AttributeLDAPDisplayName` | `winlog.event_data.AttributeLDAPDisplayName` | 0 | 1 |
| `AuthenticationPackageName` | `winlog.event_data.AuthenticationPackageName` | 0 | 1 |
| `Channel` | `winlog.channel` | 0 | 1 |
| `ComputerName` | `winlog.computer_name` | 1 | 0 |
| `Image` | `process.executable` | 0 | 1 |
| `ProcessId` | `process.pid` | 0 | 1 |
| `SamAccountName` | `winlog.event_data.SamAccountName` | 0 | 1 |
| `ServiceStartType` | `winlog.event_data.ServiceStartType` | 0 | 1 |
| `rule.name`  _(floor)_ | `rule.name` | 0 | 1 |
| `rule.uuid`  _(floor)_ | `rule.uuid` | 0 | 1 |

### `system`  (21 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 20 | 3 |
| `host.name`  _(floor)_ | `host.name` | 20 | 1 |
| `ImagePath` | `winlog.event_data.ImagePath` | 1 | 19 |
| `ServiceName` | `winlog.event_data.ServiceName` | 0 | 20 |
| `AccountName` | `user.name` | 0 | 13 |
| `StartType` | `winlog.event_data.StartType` | 0 | 13 |
| `ServiceType` | `winlog.event_data.ServiceType` | 0 | 6 |
| `Provider_Name` | `winlog.provider_name` | 1 | 0 |
| `User` | `user.name` | 0 | 1 |

### `taskscheduler`  (1 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 0 | 1 |
| `TaskName` | `winlog.event_data.TaskName` | 0 | 1 |
| `host.name`  _(floor)_ | `host.name` | 1 | 0 |

### `wmi`  (3 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `User` | `user.name` | 0 | 3 |
| `host.name`  _(floor)_ | `host.name` | 3 | 0 |
| `EventID` | `event.code` | 0 | 2 |
| `Operation` | `winlog.event_data.Operation` | 0 | 2 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 1 |

### `wmi_event`  (1 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `Consumer` | `winlog.event_data.Consumer` | 0 | 1 |
| `EventType` | `winlog.event_data.EventType` | 0 | 1 |
| `Operation` | `winlog.event_data.Operation` | 0 | 1 |
| `Query` | `winlog.event_data.Query` | 0 | 1 |
| `User` | `user.name` | 0 | 1 |
| `host.name`  _(floor)_ | `host.name` | 1 | 0 |
