## OWASP and Security Frameworks
What do you know about OWASP?

What are the OWASP Top 10 of 2021?

What are the SANS Top 25?

Mention the OWASP risk rating methodology.

Mention the basic design of OWASP ESAPI.

What are the Secure Design Principles

Which tools have you used for SAST?

What is the difference between SAST and SCA?

## Web and HTTP Security Vulnerabilities and Techniques

### SQLi
How well you understand SQLi (SQL Injection)?
What is SQL Injection, and what are the best practices to avoid it?
What is SQL Injection, and how can it be effectively prevented?
Describe how you would secure a SQL database against common vulnerabilities.
Explain a blind SQL injection attack. How does a web application firewall (WAF) detect and prevent SQL injection attacks?

### XSS
What is XSS (Cross-Site Scripting), and how would you prevent an XSS attack? What are the different types of XSS, and how do they differ?
What is Cross-Site Scripting (XSS), and how can it be mitigated?
What are the different types of XSS (Cross-Site Scripting), and how do DOM-based XSS and Reflected XSS differ? What is the role of DOM in DOM-based XSS?
What are effective recommendations for mitigating XSS vulnerabilities?
Explain a DOM-based cross-site scripting attack. Is input validation sufficient to prevent XSS?
Explain DOM XSS.
Can DOM XSS be stored?
Can the CSP (Content-Security-Policy) header mitigate DOM-based XSS?
Do the HttpOnly cookie and X-XSS-Protection header mitigate cross-site scripting attacks?
How do you exploit XSS in a POST request?
You’ve found XSS issue in the source code, what will be your best approach to address this?
What is the purpose of the HttpOnly attribute for cookies, and how does it protect against XSS attacks?
What are the different types of XSS (Cross-Site Scripting) attacks, including reflected, persistent, and DOM-based XSS?

### CSRF
Explain the difference between Cross-Site Request Forgery (CSRF) and Same-Origin Policy (SOP).
What is CSRF (Cross-Site Request Forgery), and what measures can be taken to prevent it?
What is CSRF (Cross-Site Request Forgery), and how can you prevent a CSRF attack?
Does SOP mitigate CSRF attacks?
What is CSRF, and how does it relate to the Same-Origin Policy?

### XXE Injection
What is XXE Injection (XML External Entity Injection), and how can it be detected and avoided?

How dangerous is XXE Injection, and what are its potential impacts, such as XXE to Remote Code Execution (RCE)?

Recommend XXE mitigation for an application that requires DTDs to be called because of a business requirement.

### Insecure Deserialization
What is insecure deserialization, and how can it be detected in both black box and white box testing? What can be the consequences of insecure deserialization, and how can it be avoided?

### IDOR
What is IDOR (Insecure Direct Object References), and how does it differ from missing function level access control? What are the methods to prevent and remediate IDOR vulnerabilities?
What are the differences between IDOR (Insecure Direct Object Reference), Missing Function Level Access Control, and Privilege Escalation?

### CORS
Explain CORS and SOP (Same-Origin Policy).
What is the same-origin policy, and how does CORS (Cross-Origin Resource Sharing) work?
What is the Same-Origin Policy and how does it enhance web security?
Explain CORS (Cross-Origin Resource Sharing) and how it controls access to resources on different domains.

### SSRF
How do you exploit SSRF attacks?

### Directory Traversal
What is directory traversal, and what methods are used to prevent it?

### RCE
What is remote code execution (RCE), and how does it relate to privilege escalation?


### Misc
What is Password Spraying, and Clickjacking? How can each of these vulnerabilities be mitigated?
What is a session fixation attack, and what strategies can be used to remediate it?
What is the difference between white box and black box testing, and which is more suitable for different scenarios?
How would you perform a security/penetration test on a web application, covering various scenarios?
How does a web application firewall (WAF) detect and prevent attacks?
Mention the risks that involve unsecure HTTP cookies with tokens.
How to defend against multiple login attempts?
Discuss the Phishing issues.
What approach can you take to defend against phishing attempts?
What is Security Testing?
What is “Vulnerability”?
What is file enumeration?
What is a bind shell, and how does it differ from a reverse shell?
How does a reverse shell work, and what are its typical use cases in an attack scenario?
What is email spoofing, and how can it be detected and prevented?
How does IP address spoofing work, and what are its potential impacts?
What is MAC address spoofing, and how can it be mitigated?
How can biometric spoofing be performed, and what are the countermeasures?
What is ARP spoofing, and how does it affect network security?
What will be your test case for a file upload functionality?
If you have API calls that need to fetch credentials, what is the secure way to store secrets and make them available for API calls?
You found that one of your applications uses a vulnerable dependency named X, what would be your best approach to address this issue?
What is HSTS (HTTP Strict Transport Security)?
What is a Preflight request?
What is a Double-Submit Cookie and SameSite Cookie Attribute?
What data does the shadow file contain?
What is SPF, DKIM, and DMARC?
Why is Whitelisting preferred over Blacklisting in security?
What is HSTS (HTTP Strict Transport Security), and how does it improve security for websites?
What is Certificate Transparency and why is it important for verifying SSL/TLS certificates?
What was HTTP Public Key Pinning (HPKP), and why was it deprecated by Google Chrome?
How does local file inclusion differ from remote file inclusion, and why is remote file inclusion less common today?
What are the three primary ways to attack a system: social, physical, and network?
What are common social engineering attacks (e.g., phishing, spear phishing, baiting, tailgating), and how do cognitive biases play a role?
What physical attacks might be used to compromise a system (e.g., accessing hard drives, booting from Linux, keyloggers)?
What network-based attacks can be performed (e.g., using Nmap, finding CVEs, interception attacks)?
What are exploit kits and drive-by download attacks, and how do they work?
What are some of the common XML parsers?
What is web cache deception?
What is HTTP request smuggling?

