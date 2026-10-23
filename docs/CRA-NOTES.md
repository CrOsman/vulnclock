# What the Cyber Resilience Act asks of a software maker

Read from the official text of Regulation (EU) 2024/2847 (OJ L, 20.11.2024, [ELI](http://data.europa.eu/eli/reg/2024/2847/oj)) on 22.10.2026, plus the ENISA Single Reporting Platform (SRP) [FAQ](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions) and [glossary](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2). A working summary, not legal advice: check the official text before relying on it.

## Dates (Article 71(2))

| From | What applies |
| --- | --- |
| 11 June 2026 | Chapter IV, notification of conformity assessment bodies (Articles 35-51) |
| 11 September 2026 | Article 14, reporting of actively exploited vulnerabilities and severe incidents |
| 11 December 2027 | Everything else: essential requirements, technical documentation, conformity assessment, EU declaration of conformity, CE marking |

## Reporting (Article 14), in force now

| | Actively exploited vulnerability (14(1)-(2)) | Severe incident (14(3)-(5)) |
| --- | --- | --- |
| Early warning | Within 24 h of becoming aware; Member States where the product is available | Within 24 h; also whether unlawful or malicious acts are suspected |
| Notification | Within 72 h: product, general nature of the exploit and the vulnerability, measures taken, measures users can take, how sensitive the information is | Within 72 h: nature of the incident, initial assessment, measures taken and for users, sensitivity |
| Final report | No later than 14 days after a corrective or mitigating measure is available: description with severity and impact; malicious actor if known; details of the security update | Within one month after the notification: detailed description with severity and impact; type of threat or root cause; applied and ongoing mitigation |

- **Where:** the ENISA SRP, endpoint of the CSIRT designated as coordinator of the Member State of the main establishment, i.e. where cybersecurity decisions about the product are predominantly taken (otherwise the establishment with most employees). 14(7). No API yet; web form, EU Login with MFA (SRP FAQ).
- **Severe incident:** affects or can affect availability, authenticity, integrity or confidentiality of sensitive or important data or functions, or led or can lead to malicious code in the product or the user's systems. 14(5).
- **Users:** inform the impacted users (where appropriate all users) and what they can do, where appropriate machine-readable. 14(8).
- **Small companies:** no administrative fines for microenterprises and small enterprises for missing the 24 h early-warning deadline; the obligation itself stays. 64(10)(a).
- **Before 11.9.2026:** exploitation you already knew of before that date need not be reported retrospectively (SRP FAQ).

## Vulnerability handling (Annex I, Part II), from 11.12.2027

1. Identify and document vulnerabilities and components, including an SBOM "in a commonly used and machine-readable format covering at the very least the top-level dependencies".
2. Address and remediate without delay, including by security updates; separate from functionality updates where technically feasible.
3. Regular tests and reviews of security.
4. After an update, publicly disclose fixed vulnerabilities (description, affected product, impact, severity, remediation); delay only in justified cases.
5. A coordinated vulnerability disclosure (CVD) policy.
6. A contact address for reporting vulnerabilities.
7. Secure distribution of updates, automatic where applicable.
8. Security updates without delay and free of charge, with advisory messages.

The Commission may set the SBOM format by implementing act (13(24)).

## Other manufacturer duties (Article 13)

| Duty | Reference |
| --- | --- |
| Documented cybersecurity risk assessment, kept in the technical documentation | 13(2)-(4) |
| Due diligence on third-party and open-source components; report their vulnerabilities upstream | 13(5)-(6) |
| Support period of at least 5 years (or the expected use time if shorter), justified in the technical documentation | 13(8) |
| Each security update stays available 10 years or the rest of the support period, whichever is longer | 13(9) |
| Technical documentation and EU declaration of conformity kept 10 years or the support period | 13(13) |
| Single point of contact for users, also for vulnerability reports, not only automated tools | 13(17) |
| End date of the support period (month and year) shown at purchase | 13(19) |
| EU declaration of conformity (Annex V) or the simplified one (Annex VI) with the product | 13(20) |
| User information and instructions (Annex II) | 13(18) |

## What the required documents contain

- **Annex V, EU declaration of conformity:** product identification, manufacturer, sole-responsibility statement, object of the declaration, conformity statement, standards or specifications applied, notified body where applicable, place, date, name, function, signature.
- **Annex VI, simplified declaration:** "Hereby, [manufacturer] declares that the product with digital elements type [type] is in compliance with Regulation (EU) 2024/2847. The full text of the EU declaration of conformity is available at the following internet address: ..."
- **Annex VII, technical documentation:** general description (purpose, software versions, user information), design and vulnerability handling (architecture, SBOM, CVD policy, contact address, update distribution), production and monitoring processes, risk assessment, support period rationale, standards applied or solutions adopted, test reports, the declaration of conformity.
- **Annex II, user information:** manufacturer and contact, single point of contact and CVD policy, product identification, intended purpose and security properties, foreseeable risks, declaration address, support type and end date, secure use, updates, decommissioning and data removal, how to turn off automatic security updates.
