# Forge — Local-only AI Coding Agent & Organization Q&A

Forge is a local-first MVP with two workflows: review-gated code proposals for a repository, and question answering grounded in an administrator-imported organization CSV. Both workflows use a model running on the same computer through Ollama's local OpenAI-compatible API. The application rejects non-loopback model endpoints and redirects.

This is a single-user local prototype, **not** a production enterprise platform. It has no employee login or per-person access control and must not be shared with multiple employees or exposed to a network. It does not claim SOC 2, HIPAA, GDPR, ISO 27001, PCI DSS, FedRAMP, an SLA, or measured productivity/cost savings.

## Private organization Q&A

1. Start the local Ollama model described below.
2. Open Forge at <http://127.0.0.1:8000> and choose a UTF-8 `.csv` file containing data you are authorized to process.
3. Ask a focused question. Forge retrieves a bounded set of matching rows and sends that context only to Ollama on `127.0.0.1`.
4. Review citations to the original CSV row numbers. Remove the local dataset when you no longer need it.

The CSV is stored in a local SQLite file with owner-only file permissions. The MVP refuses columns that appear to contain highly sensitive data (such as salary, bank, health, government-ID, address, or phone fields), limits imports to 1.5 MB, 5,000 rows, 30 columns, 500 characters per cell, and limits model context to 25 matching records/16,000 characters. Pattern-based header checks are not a full data-classification system. The database is **not encrypted by Forge**; enable FileVault/full-disk encryption and protect the account on the Mac.

The model is instructed to cite source rows and not invent unsupported facts. Retrieval is simple local keyword matching—not semantic search—and larger datasets can produce an incomplete sample. Treat answers as suggestions and check the source records before acting on them.

Example UTF-8 CSV header and synthetic row:

```csv
employee_id,name,team,role
E-001,Example Person,Support,Engineer
```

The local audit trail records import/clear events and counts of cited sources, not questions, CSV contents, or employee names. It does not identify a person; this prototype assumes a single authorized local administrator.

## Install the local model

Install Ollama for macOS using the official Ollama application, then open Terminal. Downloading an approved model requires internet access once; **Forge does not send your CSV, questions, or source code to the internet or to the model publisher**.

```bash
ollama pull qwen2.5:3b
```

If Ollama is not already running in the background, start it in a separate Terminal:

```bash
ollama serve
```

Keep that Terminal open. Verify the model is installed with:

```bash
ollama list
```

Choose a different already-installed local model with `AI_MODEL`. Larger models may require more memory. Do not use Ollama Cloud or another remote/cloud model; Forge rejects model names marked `cloud` or `remote`.

## Start Forge

Requires Python 3.11 or newer. From the Forge repository root:

```bash
AGENT_WORKSPACE_ROOT="/absolute/path/to/repository-to-edit" \
AGENT_PORT=8000 \
python3 run.py
```

Open <http://127.0.0.1:8000>. No cloud API key is needed. If port 8000 is busy, use `AGENT_PORT=8001` and open <http://127.0.0.1:8001>. The server only binds loopback.

## Local configuration

| Variable | Default | Purpose |
|---|---|---|
| `AGENT_WORKSPACE_ROOT` | Current directory | Repository the coding agent may inspect and, after approval, modify |
| `AGENT_HOST` | `127.0.0.1` | Loopback addresses only; remote binding is refused |
| `AGENT_PORT` | `8000` | Local web port |
| `AI_BASE_URL` | `http://127.0.0.1:11434/v1` | Local model endpoint; external hosts and redirects are blocked |
| `AI_MODEL` | `qwen2.5:3b` | Model name served by local Ollama |
| `AI_API_KEY` | unset | Optional credential for a local model server only |
| `AI_MAX_TOKENS` | `1800` | Coding-agent completion cap (256–4096) |
| `ORG_DATA_DB` | `~/.local/share/enterprise-ai-agent/org-data.sqlite3` | Local organization CSV database |
| `AGENT_AUDIT_DB` | `~/.local/share/enterprise-ai-agent/audit.sqlite3` | Local hash-chained audit database |

Do not set `AI_BASE_URL` to a cloud provider. Forge refuses non-local model endpoints even if configured, refuses model names marked `cloud`/`remote`, and does not follow model-server redirects. The computer/Ollama installation must still be managed to ensure it serves the downloaded local model.

## Coding-agent safeguards

- **One-pass workflow:** one local model request plans, drafts, reviews, and proposes tests/deployment notes.
- **Bounded context:** at most five relevant text files/12,000 characters; common generated directories and files that trigger secret patterns are skipped.
- **Review before write:** inspect a proposal before explicitly approving it. Unsafe paths, symlinks, stale files, and likely credentials are rejected.
- **No hidden execution:** generated code and suggested tests are not executed; deployment is never automated.
- **Local protections:** loopback-only HTTP service, cross-origin checks, request/file-size bounds, browser security headers, owner-only local SQLite files, and audit-chain verification at `GET /api/audit/verify`.

Secret detection is pattern-based and cannot guarantee that every sensitive value is caught. File replacements are atomic individually, not as one multi-file transaction. Keep backups and version control enabled.

## Workflow and safeguards

1. Describe one scoped code change or ask a focused question about the imported local data.
2. Forge selects bounded context and queries the local model only.
3. Review source citations for organization answers or inspect the coding proposal and security findings.
4. Explicitly approve a coding proposal before Forge writes it. Organization data can be removed from the local store from the UI.
5. Run tests and inspect the resulting diff yourself; Forge does not execute generated code.

Code writes are limited to eight regular text files, each at most 256 KiB. The coding audit database stores task IDs, event names, status, and file counts—not prompts, code, or credentials. The local audit hash chain can make accidental edits detectable, but a local administrator can still alter the database; it is not an immutable compliance log.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Roadmap before production

Before multi-user or production use, add authenticated identity and role-scoped access to each dataset, tenant isolation, encryption-at-rest/key management, policy-based approvals, isolated execution sandboxes, signed/provenance-tracked patches, a protected audit pipeline, data-classification controls, independent security reviews, backups, and the relevant compliance audits. Do not expose this prototype to a network or describe it as certified.

## License

Apache License 2.0. See [LICENSE](LICENSE).
