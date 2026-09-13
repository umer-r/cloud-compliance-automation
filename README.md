# Cloud Compliance & Security Automation

Central library of my automated security controls, guardrails, and compliance playbooks designed for cloud environments.

## Purpose of this Repository

Modern cloud environments require continuous security and compliance rather than manual point-in-time audits. The goal of this repository is to:
- **Eliminate Common Misconfigurations**: Replace broad or risky settings with secure, least-privilege defaults.
- **Automate Compliance Frameworks**: Provide ready-to-deploy automations that map directly to industry standards such as **CIS Benchmarks**, **SOC Type II**, **PCI-DSS v4.0**, etc.
- **Leverage Serverless & Event-Driven Architecture**: Use native cloud services to keep resources hardened automatically with zero maintenance overhead.

---

## Repository Structure

Automations are organized by cloud provider and project. Each automation has its own self-contained folder with its code, IAM policies, architecture diagrams, deployment templates, and a dedicated documentation guide.

---

## Available Automations

| Automation | Cloud | Description | Key Compliance Mappings |
| :--- | :---: | :--- | :--- |
| [**Cloudflare Origin Protection & Prefix List Reconciliation**](./aws/cf-whitelisting-reconciliation/) | AWS | Synchronizes Cloudflare proxy IP ranges into AWS Managed Prefix Lists and alerts via SNS when ranges change. Eliminates `0.0.0.0/0` on web ports. | CIS AWS 5.2/5.3, SOC 2 (CC6.6, CC6.7, CC7.1), PCI-DSS 1.2/1.3, NIST SC-7 |

---

## Design Standards for New Automations

Every automation added to this repository follows these principles:
- **Fail-Closed by Default**: If an external API or dependent check fails, the automation halts safely without damaging existing security rules.
- **Audit-Ready**: Changes are logged, tagged, and dispatched to alerting channels (such as Amazon SNS).
- **Least Privilege**: IAM policies grant only the exact permissions needed for the automation to function.
