## IOC (Indicators of Compromise)
- What is an indicator of compromise (IOC), and how are they typically shared among organizations or groups?

- What are common examples of specific details that can be considered IOCs (e.g., IP addresses, hashes, domains)?

## Signals
- What tools or methods are used to create signals for detecting potential threats (e.g., honeypots, Snort)?

- How do systems triage signals and what tools are commonly used for this purpose (e.g., SIEM like Splunk)?
What are the challenges associated with automatic triage of collated logs and machine learning for alerts?

- How do notifications and analyst fatigue impact the effectiveness of alert systems?

- What systems are designed to help determine whether an alert is indicative of a real hack?

What types of alerts are there, and how are they triggered?

How can you find the root cause of an incident?

How can you differentiate between symptoms and the root cause of an incident?

How can you build a timeline of events during an incident?

Why is it important to assume good intent, and how can you work effectively with others during an incident?

How can you prevent future incidents with the same root cause?

How would you handle an incident response scenario where a Firefox version is reported to be infected by malware?

What would you do to automate the elimination of false positives in a security monitoring system?

Walk me through your process of finding and remediating a security vulnerability in a product.

In a scenario where AWS EBS service is suspected of malicious activity, how would you investigate?

If PC is attacked, what kind of measures do you take?

Where do you start if your PC is effected or have any issues in the network?

## Intrusion Detection
- What is Intrusion Detection?

- What are Intrusion Detection Systems and their types?

- What are the advantages of an intrusion detection system?

- What is Host Intrusion Detection System (HIDS)?

- What is NNIDS?

- Mention three intruder classes.

- What is an Intrusion Detection System (IDS), and how do signature-based and behavior-based IDS differ?

- How do you write Snort/Suricata/YARA rules for detecting threats?

- What is a Host-based Intrusion Detection System (HIDS), and how does it differ from network-based IDS?

- What is Security Information and Event Management (SIEM), and how does it help in detecting and responding to security incidents?

- What is Splunk, and how is it used in threat detection?

- How does Arcsight contribute to security information and event management?

- What are the key features of Qradar in the context of security monitoring?

- How does Darktrace utilize machine learning for threat detection?

- What functionalities does Tcpdump provide for network analysis?

- How can Wireshark be used to analyze network traffic?

- What is Zeek (formerly Bro), and how does it assist in network security monitoring?

- Mention the challenges for the successful deployment and monitoring of web intrusion detection.


## Mitigations
- What is Data Execution Prevention (DEP) and how does it protect against exploits?

- How does Address Space Layout Randomization (ASLR) enhance system security?

- What is the Principle of Least Privilege and how can it be applied to applications like Internet Explorer?

- What is code signing and why is it important for kernel mode code?

- How do compiler security features help prevent buffer overruns?

- What are Mandatory Access Controls (MACs) and how do they differ from 
Access Control Lists (ACLs)?

- What does "insecure by exception" mean, and how does it relate to security practices?

- Why is it important not to blame users in security design, and how should technology be designed to build trust?

## Incidence Response
- What are the key steps in the SANS PICERL model (Preparation, Identification, Containment, Eradication, Recovery, Lessons learned)?

- What are the key elements of Google’s IMAG (Incident Management At Google) model?

- How do privacy incidents differ from information security incidents, and when should you involve legal, users, managers, or directors?

- How would you run a scenario from start to finish in incident management?

- How should responsibilities be delegated during an incident?

- Who is assigned to each role in the incident response team?

- How should communication be managed and what methods of communication are effective?

- When should an attack be stopped, and how is this decision made?

- What risks are associated with alerting an attacker during an incident?

- What are some common ways attackers may clean up or hide their attacks?

- When and how should upper management be informed about an incident?

- How are priorities assigned during an incident, and what metrics determine priority changes?

- How can playbooks be utilized during an incident response?

## Signatures
- What are host-based signatures, and how are they used in detecting threats (e.g., registry changes, file modifications)?

- How are network signatures used to identify threats, such as attempts to contact command and control (C2) servers?

- Anomaly / Behavior-Based Detection

- How does an IDS (Intrusion Detection System) use a model of “normal” behavior to detect anomalies?

- What types of unusual behaviors might be flagged by anomaly-based detection (e.g., unusual URLs, atypical user login times)?

- How can anomaly-based detection be tuned to increase log verbosity for suspicious actions within a network?


## Logs
- What type of DNS queries might indicate suspicious activity?

- How can HTTP headers reveal potential security issues?

- What role does metadata (e.g., author of file) play in forensic analysis?

- How can traffic volume and patterns be indicative of a security incident?

- What can execution logs reveal about potential security threats?

- How do you ensure that logging and monitoring are implemented securely and do not expose sensitive information?

## Digital Forensics
- What is Evidence Volatility

- How does evidence volatility differ between network, memory, and disk forensics?

## Network Forensics
- What role do DNS logs and passive DNS play in network forensics?

- How does NetFlow analysis contribute to network forensics, and what are its sampling rates?

## Disk Forensics
- What is disk imaging, and why is it important in disk forensics?

- What are the differences between various filesystems (e.g., NTFS, ext2/3/4, APFS)?

- How are logs (e.g., Windows event logs, Unix system logs) used in disk forensics?

- What is data recovery (carving), and how is it performed?

- What are some common tools used in disk forensics (e.g., Plaso/Log2Timeline, FTK Imager, EnCase)?

## Memory Forensics
- What is involved in memory acquisition, and how does it differ between footprint and smear?

- How do virtual and physical memory differ, and why is this distinction important?

- What are memory structures, and how do they impact memory forensics?

- How do kernel space and user space differ in terms of memory forensics?

- What tools are commonly used for memory forensics (e.g., Volatility, Google Rapid Response, WinDbg)?

## Mobile Forensics
- What are the implications of jailbreaking devices in mobile forensics?

- How does mobile forensics differ from computer forensics?

- What are the key differences between Android and iPhone forensics?

## Anti-Forensics
- What techniques do malware use to hide itself (e.g., timestomping)?

## Chain of Custody
- What is the importance of handover notes in maintaining the chain of custody during an investigation?

