# Server-side Topics

## Introduction

If you're just getting started with web application penetration testing, we highly recommend beginning with the server-side vulnerabilities covered in this section.

These vulnerabilities are generally easier to learn and practice because they focus entirely on how the server processes user input and responds to requests. Mastering these concepts will help you build a solid foundation in web security, allowing you to approach more advanced topics with confidence.

Our learning materials, detailed explanations, and hands-on labs will guide you through essential attack techniques, common misconfigurations, and exploitation methods frequently encountered during real-world penetration tests.

---

## Topics Covered

Below is the list of server-side vulnerabilities you will explore in this section:

- SQL Injection (SQLi)
- Authentication Vulnerabilities
  - Techniques for bypassing authentication mechanisms.
  - Exploiting weak or flawed login processes.
  - Enumeration attacks based on server responses.
  
  ### Labs:
  - [ ] Lab 1: [Username Enumeration via Different Responses](https://github.com/Esther7171/Web-Application-Penetration-Testing/edit/main/Wpt/Server-side_topics/Authentication_vulnerabilities/readme.md#lab-1-username-enumeration-via-different-responses)
  - [ ] Lab 2: [Username Enumeration via Subtly Different Responses](https://github.com/Esther7171/Web-Application-Penetration-Testing/edit/main/Wpt/Server-side_topics/Authentication_vulnerabilities/readme.md#lab-2-username-enumeration-via-subtly-different-responses)

- Path Traversal
  - Exploiting improper file path handling to access unauthorized files on the server.

- Command Injection
  - Injecting system commands to execute arbitrary code on the server.

- Business Logic Vulnerabilities
  - Abusing flaws in application workflows to bypass restrictions or manipulate application behavior.

- Information Disclosure
  - Identifying sensitive information leakage through server misconfigurations or error messages.

- Access Control Vulnerabilities
  - Exploiting weak authorization controls to gain access to restricted functionalities or data.

- File Upload Vulnerabilities
  - Uploading malicious files to achieve code execution or sensitive data exposure.

- Race Conditions
  - Exploiting timing issues in server-side processes to gain unauthorized access or privileges.

- Server-Side Request Forgery (SSRF)
  - Manipulating the server to make unintended requests to internal or external systems.

- XML External Entity (XXE) Injection
  - Leveraging insecure XML parsers to read files or perform server-side attacks.

- NoSQL Injection
  - Exploiting unvalidated input in NoSQL queries to bypass authentication or access data.

- API Testing
  - Identifying security weaknesses in server-side APIs, including authentication flaws and data exposure.

- Web Cache Deception
  - Manipulating cache mechanisms to serve sensitive content to unintended users.

---

