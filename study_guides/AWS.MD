# AWS Security Interview Questions

## Leadership Principles

1. Customer Obsession
Description: Leaders start with the customer and work backwards. They work to earn and keep customer trust, focusing on delivering the best experience possible. Although they pay attention to competitors, customer needs are the primary driver.
Application: This principle encourages making decisions based on what is best for the customer, even if it means sacrificing short-term gains.

2. Ownership
Description: Leaders act on behalf of the entire company, beyond just their team. They think long-term and don’t sacrifice long-term value for short-term results. They never say "that’s not my job."
Application: This principle emphasizes accountability and encourages employees to take initiative and responsibility for the company’s success.

3. Invent and Simplify
Description: Leaders expect and require innovation and invention from their teams and always find ways to simplify. They are externally aware, look for new ideas everywhere, and are not constrained by “not invented here.”
Application: Innovation and creativity are encouraged, but so is the need to make processes simpler and more efficient.

4. Are Right, A Lot
Description: Leaders have strong judgment and good instincts. They seek diverse perspectives and work to disconfirm their beliefs.
Application: This principle encourages making informed, wise decisions based on data, experience, and intuition, while also being open to new ideas and feedback.

5. Learn and Be Curious
Description: Leaders are never done learning and always seek to improve themselves. They are curious about new possibilities and act to explore them.
Application: Continuous self-improvement and a passion for discovery are valued. Employees are encouraged to stay curious and always look for ways to grow and innovate.

6. Hire and Develop the Best
Description: Leaders raise the performance bar with every hire and promotion. They recognize exceptional talent and willingly move them throughout the organization. Leaders develop leaders and take seriously their role in coaching others.
Application: The emphasis is on building high-performing teams by hiring the best talent and fostering their growth within the company.

7. Insist on the Highest Standards
Description: Leaders continuously raise the bar and drive their teams to deliver high-quality products, services, and processes. They ensure that defects do not get sent down the line and that problems are fixed so they stay fixed.
Application: This principle promotes a culture of excellence where employees are encouraged to deliver their best work and not settle for mediocrity.

8. Think Big
Description: Thinking small is a self-fulfilling prophecy. Leaders create and communicate a bold direction that inspires results. They think differently and look around corners for ways to serve customers.
Application: Ambition and vision are key. Employees are encouraged to dream big, set bold goals, and think creatively about how to achieve them.

9. Bias for Action
Description: Speed matters in business. Many decisions and actions are reversible and do not need extensive study. Leaders value calculated risk-taking.
Application: This principle promotes a culture of action and decisiveness, encouraging employees to move quickly and not be paralyzed by indecision.

10. Frugality
Description: Accomplish more with less. Constraints breed resourcefulness, self-sufficiency, and invention. There are no extra points for growing headcount, budget size, or fixed expense.
Application: This principle encourages efficient use of resources, focusing on maximizing output without unnecessary expenditure.

11. Earn Trust
Description: Leaders listen attentively, speak candidly, and treat others respectfully. They are vocally self-critical, even when doing so is awkward or embarrassing. Leaders do not believe their or their team’s body odor smells of perfume. They benchmark themselves and their teams against the best.
Application: Building trust with colleagues, customers, and partners is paramount. Transparency, honesty, and integrity are crucial.

12. Dive Deep
Description: Leaders operate at all levels, stay connected to the details, audit frequently, and are skeptical when metrics and anecdotal data differ. No task is beneath them.
Application: This principle emphasizes the importance of understanding the details, digging into data, and being thorough in analysis and execution.

13. Have Backbone; Disagree and Commit
Description: Leaders are obligated to respectfully challenge decisions when they disagree, even when doing so is uncomfortable or exhausting. They have conviction and are tenacious. They do not compromise for the sake of social cohesion. Once a decision is determined, they commit wholly.
Application: Constructive conflict is encouraged, but once a decision is made, everyone must commit to it, regardless of their initial stance.

14. Deliver Results
Description: Leaders focus on the key inputs and deliver them with the right quality and in a timely fashion. Despite setbacks, they rise to the occasion and never settle.
Application: This principle underscores the importance of achieving results and meeting goals, even in challenging circumstances

## General
- How would you find evidence of malicious activity within the services like AWS EBS, Application using Lambda etc.

This is to check if the person have experience with GuardDuty, CloudTrail, Config and have worked on any such malicious activities in past. If so, what all he/she did.

- CloudTrail vs CloudWatch and explain in depth from security perspective.

Person has to work on CloudTrail functionalities more often and has to be good at incident/event analysis. Also, to check whether an interviewee is aware about CloudWatch.

- How IMDSv1 is vulnerable to SSRF, explain.

There are many org wide admins, developers of whoever launch instance, by default AWS creates v1 reference. This can lead to key stealing, privilege escalation etc. through SSRF or sometimes even through curl commands. Is person aware of IMDSv1 and how IMDSv2 solves SSRF issue.

Did you implement IMDSv2 and how it fixed SSRF? References:
https://medium.com/@shurmajee/aws-enhances-metadata-service-security-with-imdsv2-b5d4b238454b
https://www.cyberbit.com/blog/uncategorized/aws-imds-v2-secures-ssrf-vulnerability/
https://www.accurics.com/blog/security-blog/aws-cloud-security-protect-ssrf/
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/
https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af
https://www.youtube.com/watch?v=2B5bhZzayjI (re:Invent SEC310)

- How logs are stored in AWS and how you can monitor those?

- Can you analyse and explain risk and security issues for ElasticSearch services?

- When should you use TGW? is there any security improvement for using this?

- Should we expose Database access publicly or to web application directly?

- Can you help me to understand the security posture for Wordpress site being hosted in AWS?

- Do you have experience in AWS services security design and enforcement review or documentation?

- What issue you see when any API endpoint is exposed to public?

- There is a security group names as default and have port 22, 25, 53, 80,443, 3679, 3306, 9001. Do you see any issue here?

- Have you worked on Backup security and monitoring. Can you explain?

- We want to enable SSO and integrate a tool call Trello in our AWS environment where other applications are hosted. What security posture you think we should work on to keep everything secured?

- How the security alerts of AWS resources being captured and sent to security people automatically?

- Have you worked on GuardDuty? It has lots of false positives. Do you have any suggestions to reduce false positives.

- Can you explain how to use and when to use Access key id and Principal id with one example?

- What are the different data sources for GuardDuty?

- What are the various options/features you have worked in GuardDuty?

- I need to get an alert to slack/mail, whenever my backend APIs start giving 5xx in CloudWatch, how would you achieve that?

- RTO (Recovery Time Objective) vs RPO (Recovery Point Objective)

## Data Security
How do you secure data transfer in transit?
Do you agree that we need to enable data encryption at rest by default?
Scenario Based questions:
### Scenario 1 
(Lambda, SES and config rules) : Task is to create lambda function for config rules and send email using SES. I have multi account and one of the account is for organization level aggregator. Using that org aggregator account write a lambda function to retrieve all non-compliant config rules based on each aggregator. I wanted to have a list which has the following results 

Aggregator name = AggregatorTest OrgConfigRule – VPCFlowlog-o30sfig, Non_complaint, Acc No: 23135134235 Account id, Resource id, Resource type, AWS Region Account id, Resource id, Resource type, AWS Region

So above we have an email configured for aggregator test and then got the list of all OrgConfigRule then after that whatever resources are there for that org config rule you need to list out and then send email to users using SES.

## Logging and Monitoring
Data integrity for cloudtrail logs
How to get unencrypted EBS volume(s) in an easy way: config -> filter
cloudwatch -> metrics filter

## Infrastructure security
EC2 vulnerability patch management in automated way
What checks AWS Inspector does to figure out instance vulnerabilities

## Data protection
- KMS key usage: s3 bucket, file download but can’t see the object. what solution do you propose

- CMK keys auto-renew solution after 3 month (key rotation): cloudwatchevent to check it

- What comes to your mind when you have to secure RDS instance?

- When encryption by default is not enough?
- Would you suggest key rotation? why and what should be the rotation period? Justify.

## IAM
- Let's say an event is triggered and lambda does something. To make sure it works what you check in IAM

- Programming question (Depends on the role)
A non-decreasing number list is given and a target number. You need to print if target number exists in the list or print the most nearest number to the target number

- Explain below IAM policy:

{
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "DenyAllUsersNotUsingMFA",
        "Effect": "Deny",
        "NotAction": "iam:*",
        "Resource": "*",
        "Condition": {"BoolIfExists": 
                        {"aws:MultiFactorAuthPresent": "false"}
                    }
    }]
}
Explain below policy. What's wrong with this policy
{
    "Version": "2012-10-17",
    "Statement": {
    "Effect": "Deny",
    "Action": "s3:*",
    "NotResource": [
      "arn:aws:s3:::HRBucket/Payroll",
      "arn:aws:s3:::HRBucket/Payroll/*"
    ]
    }
}

## Additional Questions

- What are the top 3 things you would do if you are working on CSPM tool from the scratch.

- What and how you check if AWS resource is deployed/implemented over encrypted communication/channel.

- How do you make sure everyone in the organisation follow AWS security guideline while working with AWS Services?


- What comes in your mind when a service need cross account access?

- Question 1: What is the shared responsibility model in AWS security, and how does it apply to an AWS Security Engineer’s role?

Answer: The shared responsibility model in AWS defines the division of security responsibilities between AWS and the customer. AWS is responsible for securing the underlying cloud infrastructure, including physical security, network infrastructure, and hypervisor. As an AWS Security Engineer, your responsibility lies in implementing security measures within the customer’s AWS environment, such as access controls, data encryption, and monitoring for security threats and vulnerabilities.

- Question 2: How do you secure data at rest in AWS?

Answer: There are multiple ways to secure data at rest in AWS:
Utilizing server-side encryption with AWS Key Management Service (KMS) managed keys or customer-managed keys.
Enabling Amazon S3 server-side encryption with Amazon S3 managed keys (SSE-S3) or customer-provided keys (SSE-C).
Encrypting Amazon EBS volumes using AWS KMS keys.
Implementing database-level encryption for Amazon RDS or Amazon Redshift.

- Question 3: What are your strategies for protecting data in transit within AWS?

Answer: To protect data in transit within AWS, I would:
Enable SSL/TLS encryption for communication between services, such as HTTPS for web traffic.
Use Amazon CloudFront with AWS Certificate Manager to deliver content securely over HTTPS.
Implement Virtual Private Cloud (VPC) peering with encryption enabled.
Establish secure private network connections using AWS Direct Connect or VPN connections.

- Question 4: How would you mitigate Distributed Denial of Service (DDoS) attacks in an AWS environment?

Answer: To mitigate DDoS attacks in AWS, I would:
Utilize AWS Shield, a managed DDoS protection service, to detect and mitigate attacks.
Implement AWS Web Application Firewall (WAF) to protect web applications from common exploits and vulnerabilities.
Leverage AWS CloudFront and AWS Route 53 for distributing traffic and preventing overload on specific resources.
Configure Amazon VPC Flow Logs and Amazon GuardDuty to monitor and detect suspicious network traffic.

- Question 5: How do you ensure compliance with security best practices in AWS?

Answer: To ensure compliance with security best practices in AWS, I would:
Regularly audit and assess the security posture of AWS resources using services like AWS Config and AWS Trusted Advisor.
Implement and enforce security policies using AWS Identity and Access Management (IAM) to manage user permissions.
Continuously monitor and log AWS resources using services such as AWS CloudTrail and Amazon CloudWatch.
Stay updated with AWS security advisories and industry best practices to proactively address potential vulnerabilities.

- Question 6: How would you handle a security incident or breach in an AWS environment?
Answer: When responding to a security incident or breach in an AWS environment, I would follow these steps:

Immediately isolate the affected resources to prevent further damage or unauthorized access.
Notify the appropriate stakeholders, including management, incident response teams, and relevant legal or compliance departments.
Conduct a thorough investigation to determine the root cause and impact of the incident.
Implement remediation measures to address vulnerabilities, such as patching systems, updating access controls, and enhancing monitoring.
Document the incident, including the actions taken, lessons learned, and recommendations for preventing similar incidents in the future.

- Question 7: How do you ensure the secure configuration of AWS resources?

Answer: To ensure the secure configuration of AWS resources, I would:
Follow AWS best practices and security guidelines for each service, such as configuring security groups, using VPCs, and enabling encryption.
Regularly audit the configuration of AWS resources using tools like AWS Config and conduct security assessments to identify any misconfigurations or vulnerabilities.
Implement automated configuration management and infrastructure as code (IaC) tools, such as AWS CloudFormation or AWS Config Rules, to ensure consistent and secure resource deployment.
Continuously monitor for changes to configurations and promptly remediate any non-compliant settings.

- Question 8: How would you protect sensitive data within an AWS database?

Answer: To protect sensitive data within an AWS database, I would:
Implement encryption at rest using AWS Key Management Service (KMS) or database-specific encryption mechanisms.
Utilize secure database authentication methods, such as AWS Secrets Manager or IAM database authentication.
Apply appropriate access controls and permissions to restrict access to sensitive data.
Regularly patch and update the database to address any security vulnerabilities.
Implement database activity monitoring and logging to detect and investigate any unauthorized access or suspicious activities.

- Question 9: How would you ensure compliance with regulatory standards in an AWS environment?

Answer: To ensure compliance with regulatory standards in an AWS environment, I would:
Identify the applicable regulatory requirements, such as GDPR or HIPAA, and understand their specific security and privacy controls.
Implement security controls and practices that align with the regulatory requirements, such as data encryption, access controls, and audit logging.
Regularly assess and audit the environment for compliance using tools like AWS Config and AWS Trusted Advisor.
Implement logging and monitoring mechanisms to detect and respond to any potential compliance violations.
Stay informed about regulatory updates and industry best practices to proactively address any changes.

- Question 10: How do you stay updated with the latest AWS security trends and best practices?

Answer: To stay updated with the latest AWS security trends and best practices, I would:
Regularly review AWS security documentation, whitepapers, and official blogs to stay informed about new services, features, and security recommendations.
Participate in AWS webinars, online forums, and user groups to learn from industry experts and peers.
Engage in continuous learning through training courses, certifications, and workshops offered by AWS or authorized training providers.
Follow reputable security blogs, industry publications, and social media channels to keep up with emerging security threats and mitigation strategies.
Actively engage in knowledge-sharing and collaboration with colleagues and security communities to exchange insights and best practices
---

## Sample Interview Flow

### Round 1: Phone Screen (Elimination Round)

Problem 1 (20 minutes): I was firstly asked to review a python code and find as much security issues as I can in 15 minutes and next 5 minutes were utilized by hiring manager to discuss any 3–4 interesting issues that I reported in detail (tried to confuse me whether it is actually an issue or not (Be Confident!)) and the best part was he also told me 1 vulnerability which I missed at the end.

Problem 2 (20 minutes): Then he jumped on to threat modelling question, again I was given 15 minutes to prepare a basic threat model (due to less time) following STRIDE model and next 5 minutes were utilized by hiring manager in reviewing and cross questioning on the threat model prepared by me. This was a bit easy one and recruiter seemed to be happy with my solution and approach .

Problem 3 (15 minutes): Some basic security questions (AppSec) and Why Amazon? This went on for 15 minutes

Problem 4 (15 minutes): This was a leadership principle question (These leadership principle questions will be asked in each and every round so be prepared).

Last 5 minutes: In last I was given 5 minutes to ask anything regarding Amazon or security team.

### Round 2

Problem 1 (15 minutes): I was firstly asked to review a java code and find as much security issues as I can in 15 minutes and next 5 minutes were utilized by him to discuss remediation of almost all the security issues that I reported. In my case, for 2–3 vulnerabilities, interviewer went in detail (tried to confuse me as well but I remained confident).

Problem 2 (30 minutes): Then he jumped on to the coding problem. He was handy with some codes. He firstly asked me to choose my preferred language (I replied python). So he gave me a half written python code with all libraries imported and some parameters defined.

Question: The problem was to understand that half written code and then explain him what you understand before completing the same so as he can guide you in case you are in wrong direction and then complete the same. I remember vaguely about the code so refraining from mentioning here. This was a easy-medium problem and not a hard one.

Problem 3(10 minutes): This was a leadership principle question.

Last 5 minutes: In last I was given 5 minutes to ask anything regarding Amazon or AppSec team.

### Round 3

Problem 1 (15 minutes): In first 15 minutes I was asked questions of network security and cryptography

Problem 2 (15 minutes): In next 15 minutes I was asked about 8–9 vulnerabilities along with their remediation (not limited to OWASP TOP 10).

Question: Random vulnerabilities not limited to OWASP Top 10 (These were not straight questions but with some twists and indirect references.)

Problem 3 (15 minutes): In next 15 minutes I was asked about cloud security (if you have knowledge of some other cloud than AWS then also it is fine).

Problem 4 (10 minutes): This was a leadership principle question.

Last 5 minutes: In last I was given 5 minutes to ask anything regarding Amazon or security team.

### Round 4

Question 1 (45 minutes): In this round only 1 question was asked which was based on a threat model. Interviewer firstly asked me if i am comfortable with cloud (AWS) as the threat model diagram also included some cloud stuff.

Once I gave go-ahead, I was presented with a threat model diagram and firstly I had to explain him the whole diagram, he was fully convinced with my understanding so after that I had to perform threat model using STRIDE model and at last he cross questioned me on my answers and also cross questioned me more on cloud related stuff and their remediation as well. This went for 45 minutes.

Problem 4 (10 minutes): This was a leadership principle question.

Last 5 minutes: In last I was given 5 minutes to ask anything regarding Amazon or security team.

### Final Round

Problem (60 minutes): I was asked 3 leadership questions (each for 20 minutes). Based on my answers, he asked technical as well as leadership questions like (it can be about some specific vulnerability, some projects and it’s approach, how you lead the project, how you convinced your manager or some developer/QA to fix any specific vulnerability and what steps you took if they denied or gave high SLA time). You can even be asked questions on your bug bounty journey if you have mentioned in your resume etc. There is nothing specific for this round, you will be asked questions based on your answers and resume!

Last 5 minutes: In last I was given 5 minutes to ask anything regarding Amazon or security team. This was my last round and he told it can take 1–2 weeks for the final feedback.