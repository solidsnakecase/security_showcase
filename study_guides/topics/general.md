## General Security Knowledge
Why is it important to understand both first principles and in-depth systems knowledge?

Tools you use for security

How does file compression work?

What are stateless and stateful requests?

How is the state of a request saved in HTTP?

What are Certificate Transparency Logs?

What is the difference between Remote Code Execution, Remote Command Execution, Code Injection, Command Injection, and RCE (Remote Code Execution)?

Are open-source projects more or less secure than proprietary ones?

What is the difference between SSL Connection and SSL Session?

Explain Penetration Testing and its objectives.

How can password files be protected to prevent unauthorized access?

What are some commonly used abbreviations in software security, and what do they stand for (e.g., OSI, ISDN, SSH, TLS)?

What factors can cause vulnerabilities in a system, and how can they be mitigated?

What is ISO 17799, and what does it cover?

What is port scanning, and how is it used in security assessments?

What are the seven types of security testing as per the Open Source Security Testing methodology manual?

How would you perform network reconnaissance and prevent a DDoS attack on a website?

How do you handle common scenarios

How do you handle Developer Security Issues?

How will you scale security scope for heavy application-focused projects

What security measure would you take from a data integrity perspective

What is the difference between threat, vulnerability, and risk in the context of security?

What is Adhoc Testing, and how does it differ from other testing methodologies?

What are the key attributes considered for security testing, such as Authentication, Confidentiality, Authorization, Integrity, Availability, Resilience, and Non-repudiation?

How would an HTTP program handle state?

What is file enumeration?

Mention some factors that can cause vulnerabilities.

Mention the parameters to define an SSL session connection.

Name the two standard approaches used to protect a password file.

Explain the secure architecture of a web server.

How would you design a security strategy to protect a microservices architecture from both external and internal threats? What are the challenges you might face while designing and implementing it?

- Among Windows and Linux, which one provides more security?

- What is reconnaissance in the context of an attack, and what tools and methods are commonly used (e.g., OSINT, Google dorking, Shodan)?

- What does resource development entail in an attack scenario?

- What methods are commonly used to gain initial access to a target?

- What are some common execution techniques used by attackers (e.g., shells, scheduled tasks, WMI)?

- How do attackers ensure persistence in a compromised environment?

- What are common privilege escalation techniques?

- What methods are used for defense evasion during an attack?

- How do attackers typically access credentials?

- What is involved in the discovery phase of an attack?

- What are common methods for lateral movement within a network?

- How do attackers collect data during an attack?

- What are typical exfiltration methods used by attackers?

- What are the different command and control (C2) methods used in an attack?

- What impact can an attacker have on a compromised system or network?

## Honeypots
What are canary tokens, and how can they be used to detect malicious activity?
How do dummy internal services or web servers function as honeypots, and what can be learned from monitoring traffic to them?
Things to Know About Attackers
Why are slow attacks harder to detect, and what strategies do attackers use to create noise?
How can attackers spoof IP addresses and what methods can be used to detect such spoofing (e.g., TTL checks)?
What challenges are associated with correlating IP addresses with physical locations?

## OS Implementation and Systems
What are some common privilege escalation techniques and how can they be prevented?
What is a buffer overflow, and how can it be exploited? What methods are used to prevent buffer overflows?
How can directory traversal attacks be prevented?
What is remote code execution (RCE) and how can attackers gain shell access to a system?
How are local databases like SQLite used in messaging apps, and why is this relevant for digital forensics?

### Windows
What is the Windows Registry, and how does it interact with Group Policy?
Explain the role of Active Directory (AD) in Windows environments.
What is the BloodHound tool, and how is it used in Active Directory environments?
How does Kerberos authentication work with Active Directory?
What is Windows SMB, and how does it compare with Samba?
What is Return-Oriented Programming (ROP) and how does it relate to buffer overflows?

### *nix Systems
What is SELinux and how does it enhance system security?
How do MAC (Mandatory Access Control) and DAC (Discretionary Access Control) differ?
What is the purpose of the /proc directory in Linux systems?
What are the security implications of the /tmp directory in Linux?
What information is stored in the /shadow file, and how does it impact system security?
Explain the LDAP (Lightweight Directory Access Protocol) and how it compares to Active Directory.

### macOS
What was the Gotofail error in macOS and how did it affect SSL/TLS security?
What is MacSweeper and what role does it play in macOS security?
What are some known vulnerabilities in macOS, and what are their mitigations?

## Phishing
Could you explain what phishing is? How can it be prevented?
Phishing is a technique that deceives people into obtaining data from users. The social engineer tries to impersonate a genuine website like Yahoo or Facebook and will ask the user to enter their password and account ID.

It can be prevented by:
Having a guard against spam
Communicating personal information through secure websites only
Downloading files or attachments in emails from unknown senders
Never emailing financial information
Being cautious of links in emails that ask for personal information
Ignoring requests to enter personal information in pop-up screens