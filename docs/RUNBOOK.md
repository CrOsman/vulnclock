# When a vulnerability is exploited: the first 24 hours

For a manufacturer whose product is on the EU market. Article references are to Regulation (EU) 2024/2847; details in [CRA-NOTES.md](CRA-NOTES.md).

## Set up once, before you need it

- [ ] One person is the **Assigned Representative**: personal EU Login account with MFA ([ecas.ec.europa.eu](https://ecas.ec.europa.eu/cas/login)). Registering as Primary AR is done on the [SRP portal](https://portal.cra-srp.enisa.europa.eu/) by picking your CSIRT designated as coordinator and entering the manufacturer details; ENISA advises registering when you first need to notify, so keep these details ready.
- [ ] Know your **CSIRT designated as coordinator**: the Member State where cybersecurity decisions about the product are taken ([list](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/list-of-csirts-designated-as-coordinators)). Croatia's entry links to [ncsc.hr](https://ncsc.hr/hr/kontakt).
- [ ] The **daily check** runs (`templates/workflows/vulnclock.yml`) and its issue notifications reach someone who reads them.
- [ ] A public **security contact** exists (security.txt, an e-mail address) for people who find vulnerabilities (Annex I Part II (6)).

## When the check (or anyone) reports an exploited vulnerability

1. **Decide whether it is exploited in your product.** A vulnerability exploited somewhere else is not automatically exploited in your product. Check whether your product ships and uses the affected code path. Write down the decision, the evidence and the time.
2. **If it is, the clock starts at the moment you have reliable evidence** ("becoming aware", Article 14(2)). Open `wizard/index.html`, pick "Actively exploited vulnerability", set that moment. The deadlines appear.
3. **Within 24 h: early warning.** Title, summary, Member States, product and version. Everything else is optional at this stage. Submit in the SRP and keep the confirmation.
4. **Within 72 h: notification.** General information about the exploit and the vulnerability, measures taken, what users can do, how sensitive the information is.
5. **Fix it** without delay (Annex I Part II (2)), ship the security update free of charge with an advisory (point 8), and **tell users** (Article 14(8)); the wizard drafts the advisory.
6. **Within 14 days after the fix is available: final report.** Severity and impact, malicious actor if known, the update.
7. **After the update:** publish the fixed vulnerability (Annex I Part II (4)) and record everything in the technical documentation (Article 13(7)).

Microenterprises and small enterprises are not fined for missing the 24 h early warning (Article 64(10)(a)), but the duty to report stays.

## Severe incident instead

Same steps with "Severe incident" in the wizard: the early warning says whether unlawful or malicious acts are suspected, and the final report is due one month after the 72 h notification (Article 14(4)).
