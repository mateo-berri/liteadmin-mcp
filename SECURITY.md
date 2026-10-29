# Security

The server targets one operator-configured gateway. A tool cannot change that
target, invent an administrative route, forward arbitrary headers, or follow an
HTTP redirect. It exposes only reviewed operations present in the gateway's spec.

Local stdio runs with the administrator's configured gateway credential or, when
none is configured, one from the gateway's browser sign-in. That sign-in uses PKCE
with a loopback redirect on 127.0.0.1, accepts only the pending request's state,
and sends nothing to endpoints outside the configured gateway's origin. The
resulting access and refresh tokens are kept in an owner-only file (mode 0600 in a
0700 directory) keyed by gateway origin, and are dropped when the gateway rejects
them. Hosted
HTTP requests require each caller's own bearer credential; the server refuses
to start HTTP mode with a process-wide gateway key. The gateway's live proxy-admin
role is checked for discovery, before execution and before returning results.
The caller's own key remains the execution identity and audit actor.

The gateway evaluates the authenticated credential's route permissions and returns
them with the current identity. The connector requires this permission response,
filters discovery, and checks the concrete resource route before and after each
action. It does not infer an SSO session from a client header, token prefix or key
metadata. Full Access keys keep the gateway's unrestricted-route semantics.

Large sanitized results can be retained as short-lived in-memory snapshots.
Handles are unguessable and bound to both a keyed digest of the requesting
credential and the verified principal; another admin cannot read them. Each
read checks the current role and the source operation's current route permission.
Raw caller credentials
are not stored in the cache. Secret-returning key operations and results with
recognizable credentials bypass it and return their complete response inline.
Snapshot reads never re-execute the original operation. Expiration and capacity
limits are documented in the README; use the same server process for subsequent
reads. The existing result redaction policy is unchanged.

Full schemas remain the default, including for native client tool search. The
optional lightweight discovery mode retains individual tool names and safety
annotations. It only changes advertised parameter detail: the full live schema
still validates every call. Schema/result helpers are read-only, respect the
operation allowlist and cannot act as a generic execution dispatcher.

Read-only mode and the tool allowlist are enforced by the server, including on
direct calls to tools hidden from discovery. Model-returned provider parameters
are restricted to model and credential-name identifiers. New virtual keys are
returned to the requesting client; administrators must trust their chosen client
to handle those results. The connector does not send prompts to a model.

Administrative writes require care from the calling agent. Tool annotations and
instructions describe mutations, but client confirmations are not an authorization
boundary. A write timeout can occur after the gateway committed a change. Requests
are never automatically retried, and there is no persistent replay journal in this
server. The LiteLLM Admin Agent maintains its own request journal.

Terminate TLS at a trusted proxy for remote deployment. Exclude authorization
headers and request/response bodies from proxy logs. The process logs no tool
arguments or results. The HTTP service persists no credentials, and credentials
are never placed in URLs.

Report vulnerabilities using this repository's private Security Advisories when
available or your established private contact with Berri AI. Do not include live
credentials in public issues.
