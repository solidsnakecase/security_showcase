## Sort Me

Symmetric vs. Asymmetric Encryption which is faster and why?
What important problem does asymmetric cryptography solve? 
Why don’t we just use symmetric/asymmetric cryptography for everything? 

Hashing: Know all important properties (non-reversible, avalanche effect, quick computation, collision-resistant, deterministic)
hashing vs. encryption
How are passwords  hashed (using a salt, hashing is done multiple times to slow down attackers calculating the hash, through brute force or other tactics, all of this is often done using a key derivation function/password-hashing function). 
What are the effects of having a high iteration count for hashed passwords (whatever hashing you do on a password to slow down attacks, will be done when a user logs in)?
What is the tradeoff of not increasing the password iteration count too high (as users will experience more lag when logging in (the web server will need to take the password entered by the user, hash it multiple times, add in a salt the server knows then compare it with the hash stored in the database)). 
What is a hash collision? 
What makes a good or bad hash function? 
Give examples of how hashing is used besides passwords?
Salt and Pepper: Difference between both and why the salt is usually stored in plaintext.

Transport Layer Security (TLS): What it does, all handshake steps, modern/secure versions used (TLS 1.2 and 1.3), cipher suites (what each part of the cipher suite represents). 
Does TLS use TCP or UDP (technically, a trick question as TLS isn’t tied to any transport protocol but the answer an interviewer would likely expect is TCP)? 
Does TLS require TCP (it doesn’t as it only needs a reliable transport protocol, which TCP provides for the internet)?

Advanced Encryption Standard (AES): AES Modes (GCM vs. CBC). 
Which mode is more secure and why, (AES versions (256, 384, 512), AES always encrypts in 128 bits at a time, AES-128 is strong enough, though AES-256 is recommended.)
Plaintext vs. Ciphertext vs. Cleartext: Just knowing the definitions of each is enough.

Elliptic Curve Cryptography (ECC) and RSA: Acknowledgement that asymmetric keys need to be larger to achieve the same level of security as symmetric keys. Asymmetric keys are weaker due to the complex math behind them. Bonus points if you know why. 
Know the key exchange process for an asymmetric cryptographic algorithm. Other uses of asymmetric cryptography besides key exchange. 
Why prime numbers are important in cryptography? 
Why computers struggle to calculate prime numbers?
One-time Pad: Unlikely to come up but I think you’ll impress your interviewer if you remember this.
Cryptographic Keys: The strength of the encryption is dependent on the strength of the key (size and entropy) and other factors (i.e. strength of encryption algorithm). 
Different forms of key derivation (PRNG-generated key (i.e. using Random/SecureRandom class in Java), key generated via asymmetric cryptography, key derivation functions. 
Know the name of a key derivation function (i.e. PBKDF2) and why they’re used when generating things like passwords. 
What is key stretching?
Entropy: What it is and how it relates to cybersecurity.
SSL/TLS Certificates: Why they’re important, understand how its related to the padlock icon showed on browsers, certificate authority, Java truststore vs. keystore, self-signed certificate.
XOR (Exclusive Or — a boolean operation): Why XOR is extremely important in cybersecurity.
Types of Encryption: Payload encryption (i.e. encrypted HTTP body) vs. in-transit encryption (i.e. TLS) vs. at-rest encryption (i.e. encrypting data stored on a hard drive/SSD).
Nonce: Define it and give an example of how it can be used (i.e. in an encryption algorithm, a nonce can be used to add more entropy). 
What is an initialization vector (IV)? Give an example of its usage. 
What is the difference between an IV and a nonce?
Random Number Generators: Understand why computers can’t generate truly random numbers? This is why random number generators used by computers, are called “pseudorandom” (fake) number generators (PRNGs).
Secrecy: Forward secrecy (aka perfect forward secrecy).
Crypto Algorithms: Know the names of popular crypto algorithms (new and old): ECDH, ECHDE, AES, DES, 3DES, RC4, RC5, SHA1, RSA, SSL, TLS. This is just in case you get asked to name algorithms, give examples of old algorithms or some other trivia-like question.
Password Attacks: Dictionary attack, rainbow table attack
Databases: SQL injection (what it is, how to protect against it, knowing that its a common vulnerability)
Networking: Denial of service (DoS) attack , distributed denial of service (DDoS) attack, man-in-the-middle attack
Perfect Security: There’s no such thing as “perfect security”. A secure system is only as strong as the weakest link (which is often the user). There will always be new vulnerabilities discovered, employee-targeted phishing attacks and more powerful computers to help crack crypto algorithms.
Security via Obscurity: Obscurity can provide some extra security but it can’t be relied upon. The attacker sometimes knows the system/algorithm. For example, attackers know the inner workings of all popular crypto algorithms but many of them are still secure. It may be helpful to assume they do know to adopt a healthier security mindset. In the real world, most systems are obscure (their internal architecture and code base is private), so obscurity isn’t inherently bad. It’s seen as bad, typically when it’s relied upon, instead of primary defensive protections.
Security Isn’t an “End State”: Security engineers and hackers play an endless game of cat 😺 and mouse 🐭. Cats (security engineers) are adept hunters and even emit a chemical that deters mice (hackers). Although, cats alone may not stop mice from entering a home. Mice continue to learn clever ways to avoid cats (like traveling through walls). Just like these archenemies, security engineers work on improving security while hackers discover clever ways of breaking into systems.
Too Much Security: Be careful what you wish for 🪄. More security can lead to worse performance (TLS introduces more latency), a worse user experience (imagine needing two factor authentication every time you logged into your bank account on the same laptop) and can cost more money than its worth (a security company may over-engineer a security solution). For example, is a 200 character password limit necessary? Security additions like these may not add enough value to justify their investment and could deter end users depending on the consequences.
Don’t Reinvent the Wheel: Just like in software engineering, we want to reuse things (authentication services, crypto algorithms, security tools). For example, creating your own hash or encryption algorithm is discouraged as there’s likely an existing solution that’s appropriate. There’re entire teams, researchers, managers, etc. dedicated to working on popular security tools and algorithms. The consequences for an insecure implementation can be catastrophic 🔥.
Security As an Onion: What do onions 🧅 and secure systems have in common 👀? Layers and lots of them! Consider a web application for a hypothetical online clothing store called “Shopolisa” that’s hosted in the cloud (AWS). In AWS’ data centers, there’s physical locks on doors. On Shopolisa’s AWS servers, automated patching is done to apply monthly security updates to the operating system. The data of retail customers is encrypted at rest. All these protections provide security against different attacks. It’s important to not ignore other layers and additional defensive-in-depth protections.
Understanding hashing, study cross-site scripting, cross-site request forgery and server-side request forgery, OWASP Top 10, OAuth and authentication (session vs. token authentication), incident response, threat modeling and least-privilege permissions.

---

## Application Security Basics Questions
Explain your top 3 favorite OWASP Top 10 vulnerabilities and why
How does TCP 3-way handshake work?
Why is TLS important in cybersecurity and can you explain the use of TLS in detail for a website?
How SSL/TLS makes my content secured over the internet?
What happens when you type google.com in your browser?
What’s the difference between SAST and SCA?
What is SQLi and how would you prevent/mitigate it?
Explain XSS with a few examples and how it can be avoided in the current software world.
How to avoid brute-force attacks on an application. Let’s say the login page. Explain everything that comes to your mind.
Tell us about a time when you had to learn something new really quickly and how did you go about it?

## Application Security Role-based questions
Explain CORS, SOP, and CSP from security point of view
How is CSRF dangerous for an application and what must be done to prevent CSRF in an application?
Explain the concept of input validation and why it is crucial for secure coding. Provide examples.
How do you approach secure error handling and logging in an application?
Discuss the role of encryption in secure coding and some best practices for implementing it.
What are some best practices for managing secrets and sensitive information in code?
How do you ensure the security of third-party libraries and dependencies in your code?
What are the key differences between manual code review and automated static analysis?
Describe your approach to conducting a secure code review. What do you look for first?
Can you give an example of a security vulnerability you discovered during a code review and how you addressed it?
Which secure coding standards do you follow during a code review (e.g., OWASP, CERT)?
How do you balance between finding security issues and maintaining development velocity during a secure code review?
Describe the STRIDE threat modeling methodology and provide examples of each threat type.
How do you prioritize threats identified during a threat modeling exercise?
How would you integrate threat modeling into an Agile development process?

## Overall Application Security Assessment-based Questions

What would you suggest for input sanitization?

What are some strategies for ensuring secure session management in web applications?

How do you handle security misconfigurations in development and production environments?

Discuss the importance of least privilege and role-based access control in application security.

What are the challenges of implementing SDL in a fast-paced development environment, and how do you overcome them?

What are the common vulnerabilities you have experienced so far?




## Application Security Scenario-based interview questions
***Consider this section as the toughest one and mainly for senior appsec professional.***
How would you design a safe and secure password mechanism?

You use the SCA tool to find vulnerabilities in 3rd party libraries. How would you mitigate those vulnerabilities found and risks associated with third-party libraries and frameworks?

Your company is developing a new financial application that handles sensitive customer data, including banking information. Describe how you would approach threat modeling for this application. What specific threats would you consider, and how would you prioritize and mitigate them?
You are tasked with performing a secure code review for a web application that has been recently developed. During the review, you find several instances where user inputs are directly concatenated into SQL queries. Explain how you would address this issue and guide the development team to implement a secure solution.
A development team is working on a new feature that requires handling and storing user passwords. They plan to use a simple hash function (e.g., MD5) to store these passwords. As a security architect, how would you advise them on securely handling and storing passwords? Provide a detailed explanation of best practices.
During a code review, you discover that the application does not properly handle errors and exceptions. For example, stack traces are exposed to end users, which could potentially reveal sensitive information. Describe how you would rectify this situation and implement secure error handling and logging practices.
A critical vulnerability is discovered in a third-party library used extensively in your company’s application. Explain the process you would follow to assess the impact, communicate with stakeholders, and implement a fix. How would you prevent similar issues in the future?
You are designing the architecture for a new e-commerce platform that includes a web application, mobile application, and backend APIs. Outline the security architecture you would propose, including key components and technologies to ensure robust security across all layers.
How would you review an architecture to prevent an automated brute force attack or dictionary attack (think of different brute force attack techniques)?

## Secure Code Review round with code snippets
***Many companies won’t have this round, but I feel one should involve a few code snippets in an interview to check the candidate’s indirect coding knowledge from security point of view, at least for a senior role like a lead or staff role.***

Identify the security issue in this code snippet and explain how you would fix it. [Hint: Can you spot the CSRF issue here?]
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userId = $_POST['userId'];
    $newEmail = $_POST['newEmail'];
    updateEmail($userId, $newEmail);
}

Identify the security issue in this code snippet and explain how you would fix it. [Hint: Insecure desrialization]
ObjectInputStream in = new ObjectInputStream(new FileInputStream("data.ser"));
Object obj = in.readObject();
in.close();

Identify the security issue in this code snippet and explain how you would fix it. [Hint: password hashing issue]
import hashlib
def store_password(password):
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    save_to_database(hashed_password)

Which security issue it can cause? [Hint: XSS]
const userInput = request.query.userInput;
const output = "<div>" + userInput + "</div>";
response.send(output);
***Most common question asked in a secure coding round. It doesn’t need a hint I suppose.***

What issue this code snippet would cause and how would you help the developer in fixing it?
String userId = request.getParameter("userId");
String query = "SELECT * FROM users WHERE user_id = '" + userId + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

## Topics or concepts that are subjective and can check your in-depth knowledge regarding that area
1. What do you think about the good password?
This question looks very similar, but can help the interviewer to understand if the person has experience with password management related skills or not.

This question will help you to drill down to more specific questions to understand the competence of the candidate:

What is complex password
Should the password complexity be same for admin and user
How do you save the password in Database, encrypted or hashed or plain text
Do you use salt? Is it same for all the password? is it random in nature per user?
How do you make your code safe for password attacks?

2. How do you stop bruteforce attack on login/signup/forgot password page(s)?
This question helps you to understand if the person is aware of secure code development and secure design for such features and how far he/she can think. Check if the person talks about:

Captcha
CSRF token
Rate Limiting
MFA
Alert and Monitor for such anomalous behavior
Account Lockout after n failed attempts

3. What happens when you type google.com on browser
This question is just to check if the person understands the behind the curtain scene like url to IP conversion, DNS involvement, server response and so on. Listen the interviewee and see if he/she mentions below things:

How DNS resolves the url
TCP 3 way handshake
How HTTPS work and what's its advantages
How to prevent the application from MiTM (Man in The Middle Attack)

4. How SSL/TLS actually makes my content secured over the internet
This question is the extension of previous question to understand if the person understands:

How client server hello established
How key exchange happens i.e. public key or certificate
Is it symmetric or asymmetric encryption or both and when it is used
Talks about Certificate Signing Request (CSR)
What are weak ciphers and what are good SSL Cipher Suites
Able to use openssl command to see the details of ssl information
Can explain ssl format like this: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS 1.2 or TLS 1.3 and why?
What is PFS (Perfect Forward Secrecy) and why it is used?
Why https enabled website still gets hacked?

5. How you would make developers aware and involved for secure code development?
This question would help you to understand if the person has delivered any training, presentaed slides, gave demo, delivered secure coding practices workshops. See if person talks about:

## When data becomes code and how to test it
Any specific tool to fasten SQL Injection
Can you spot SQLi from code review
Experience of any SAST tool through which you can verify and validate SQLi
Mitigation for SQLi
Prepared statement in sql injection
10. Do you understand the key difference between encryption, hashing, salt, obfuscation and encoding?
11. What you should check if the website is damn slow suddenly?
12. Explain how do you handle AuthN and AuthZ?
An interviewer can assess whether the candidate has a robust and comprehensive understanding of both authentication and authorization, as well as their practical application in ensuring application security.

## Depth of Understanding:
Does the candidate understand the fundamental differences and purposes of authentication and authorization? Are they able to explain common methods and protocols for both AuthN and AuthZ?

## Practical Knowledge:
Can the candidate discuss specific implementations and technologies (e.g., OAuth, SAML, RBAC)?
Do they mention industry best practices and why they are important?

## Security Focus:
Is the candidate aware of common security risks and how to mitigate them in both AuthN and AuthZ?
Do they highlight the importance of monitoring and logging?

## Experience:
Can the candidate provide examples from past experience where they have implemented or improved AuthN and AuthZ mechanisms?
Are they able to discuss challenges faced and how they overcame them?

## Current Trends:
Is the candidate up-to-date with current trends and emerging technologies in authentication and authorization?
Do they mention advanced methods like biometrics, adaptive authentication, or zero trust models?
13. How do you implement CSP? Do you think it adds extra security for a web application? How?
Go as much deep as you can. Use this article to understand details of CSP

14. Benefits of using SoP, CORS and CSP?
Explain the basics of these concepts with one or two real world examples. Also, explain why to use these and where with few scenarios.

15. How do you handle typical developer and security clash situation?
16. List out the techniques used to prevent web server attacks
Check what all points one can cover and then you can deep dive based on the answer:

Patch management
Web Server hardening
Scanning system vulnerability
Custom vs default port
Firewall and other server setting avoiding default settings
Proper alerting and monitoring mechanism
Server log settings
17. List out the steps to successful data loss prevention controls.
See if the interviewee is able to explain below points:

Information risk profile
Assign roles and responsibilities to the technical administrator, incident analyst, auditor and forensic investigator
Develop the technical risk framework
Expand the coverage of DLP controls
Monitor the results of risk reduction
Incident Response, risk severity, playbook etc.
18. Where do we need security in SDLC phase?
19. What would do you suggest for input sanitization?
20. What have you done so far for API Security?
You can't think of application security without API security at present. However, I will cover more on API security Interview Questions in another page.

21. Why XoR is very important in Crypto world?
It's basic of Cryptography but untouched topic and I would recommend every AppSec engineer to go through basics of Cryptography.

22. How OAuth works?
23. What is SCA and how do you perform SCA?
24. What should a developer do for secrets management?
25. What is your interesting finding in secure code review?
