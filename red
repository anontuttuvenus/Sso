Finding Title

Internal Backend URL and Collector Identifier Disclosure in API Response

Severity: Low


---

Description

The GET /transaction-history/cards endpoint discloses internal implementation details within the HATEOAS (_links) section of the API response. Instead of returning links using the public API hostname, the response exposes an internal backend URL (127.0.0.1:8080) along with the authenticated user's collector identifier.

During testing, the collector identifier was not supplied in the request but was automatically populated in the response based on the authenticated session (JWT). Although no unauthorized access or privilege escalation was identified, exposing internal infrastructure details and user-specific identifiers provides unnecessary information that could assist an attacker during reconnaissance or be leveraged in conjunction with other vulnerabilities.


---

Steps to Reproduce

1. Authenticate to the application using a valid user account.


2. Send the following request:



GET /transaction-history/cards?page=1&size=20

3. Observe the API response.


4. Notice that the _links object contains URLs similar to:



http://127.0.0.1:8080/transaction-history/cards/<collector-id>/transactions

5. Verify that:

The internal backend address (127.0.0.1:8080) is disclosed.

The collector identifier is included in the generated URL despite not being provided in the request.





---

Impact

An attacker with access to the API may obtain information about the application's internal infrastructure and resource structure, including backend hostnames, service ports, and user-specific identifiers. While no direct exploitation was identified during testing, such information may aid reconnaissance efforts and facilitate further attacks if combined with other vulnerabilities.


---

Recommendation

Avoid exposing internal backend hostnames, IP addresses, or service ports in API responses.

Generate HATEOAS links using the application's public-facing base URL or return relative URLs where appropriate.

Do not expose internal resource identifiers unless they are strictly required by the client.

Review API responses to ensure only information necessary for client functionality is returned.



---

References

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
https://cwe.mitre.org/data/definitions/200.html

OWASP API Security Top 10 – API8:2023 Security Misconfiguration
https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/

OWASP ASVS – Error Handling and Information Leakage
https://owasp.org/www-project-application-security-verification-standard/
