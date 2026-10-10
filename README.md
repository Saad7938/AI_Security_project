# Policy-Gated AI Agent Security: Indirect Prompt-Injection Prototype

A small research-learning project exploring a specific security question:

> If an LLM agent is manipulated by untrusted retrieved content, can an external authorization layer still prevent access to a restricted resource?

This repository contains an intentionally insecure baseline (insecureAgent.py) and a policy-gated prototype (secureAgent.py). The assets and support scenario are fictional. The ticket operation is simulated; no real infrastructure is accessed.

## Current status

**This is an early prototype, not a production security solution or a completed research study.** The policy module and unit tests are intended to make authorization behavior independently testable without calling an LLM.

Implemented in the research-hardening branch:
- Explicit application-assigned principals (support_agent, asset_admin).
- Tool permission checks and resource classification (internal, restricted).
- Canonical asset resolution before authorization. Access decisions do not depend on whether an argument contains words such as "secret" or "admin".
- Deny-by-default behavior for unknown principals, unknown tools, and unknown assets.
- JSON Lines audit events for both allowed and blocked calls, with query summaries truncated.
- Unit tests for expected access, restricted-resource denial, aliases, unknown identities/tools, and audit logging.

Not implemented yet:
- Authentication of real users or cryptographically verified identities.
- A real database, ticketing system, secrets manager, short-lived credentials, or emergency revocation.
- Human approval workflows or a complete production audit pipeline.
- Robust retrieval isolation, multi-model evaluation, or a measured prompt-injection benchmark.
- A guarantee that prompt injection is prevented. The focus here is enforcing authorization at the tool boundary.

## Architecture

~~~mermaid
flowchart TD
    U[User request] --> A[LLM agent]
    D[Retrieved support docs: untrusted] --> A
    A --> W[Tool wrapper]
    W --> P[Policy gateway]
    P -->|deny| L[Audit event]
    P -->|allow| T[Tool implementation]
    T --> L
    T --> A
~~~

The model can propose a tool call, but its proposal is not authorization. The application assigns the principal and checks tool/resource permissions before returning asset data.

## Quick start

Python 3.10+ is recommended.

1. Create and activate a virtual environment.
2. Install dependencies:

   ~~~bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS/Linux:
   source .venv/bin/activate
   pip install -r requirements.txt
   ~~~

3. Run the authorization tests. These tests do not require an API key:

   ~~~bash
   pytest -q
   ~~~

4. To run the LLM demo, copy .env.example to .env, add your own Groq API key, then run:

   ~~~bash
   python secureAgent.py
   ~~~

Never commit .env or real API keys. The model/API demo requires network access and may incur provider-side usage.

## Example policy

| Principal | Internal asset | Restricted server |
|---|---:|---:|
| support_agent | Allow | Deny |
| asset_admin | Allow | Allow |

This is a static demonstration policy, not a user-authentication system. In a real application, the principal must be derived from a trusted authenticated session and permissions must be enforced by the backend/data source.

## Evaluation plan

The next research step is to compare the insecure baseline with the policy-gated prototype over a documented set of benign and adversarial cases. Record each case, expected result, observed result, whether sensitive data was returned, and whether a legitimate request was incorrectly blocked.

Suggested measures:
- **Unauthorized disclosure rate:** restricted-resource requests that return protected fields / total restricted-resource attempts.
- **Attack success rate:** adversarial cases that cause a prohibited tool action / total adversarial cases.
- **Benign task success rate:** legitimate requests completed correctly / total benign cases.
- **False-block rate:** legitimate requests denied / total legitimate requests.

Do not report numerical results until the cases have actually been run. Keep deterministic policy unit tests separate from LLM-based tests, since model outputs can vary.

## Limitations and threat model

- The demo assumes the application has already assigned a principal; it does not authenticate a person.
- Asset data is hardcoded and fictional.
- The gateway is a Python module in the same process, not an isolated service. A compromised process could bypass it.
- Document text is labeled untrusted in prompts and output strings, but this is not a complete prompt-injection defense.
- Audit logs are local files and are not tamper-resistant; query summaries can still contain sensitive text.
- The LLM wrapper and provider model may change. Pin dependencies and record versions before publishing formal results.

## Repository layout

- insecureAgent.py — intentionally vulnerable comparison baseline.
- secureAgent.py — LLM demo with the gateway in front of each tool.
- security_gateway.py — authorization policy, fictional inventory, and audit logging.
- tests/test_security_gateway.py — deterministic policy tests.
- .env.example — required environment variable template.

## References to investigate

- [OWASP GenAI Security Project](https://genai.owasp.org/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)

These references are starting points; this repository does not claim conformance or certification.
