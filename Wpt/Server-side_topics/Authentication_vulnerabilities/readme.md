# <div align="center">Broken Authentication / Authentication Vulnerabilities</div>

Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality. They also expose additional attack surfaces for further exploits. Understanding these vulnerabilities is crucial for strengthening authentication mechanisms and mitigating potential security risks.

## Topics Covered

- Common authentication mechanisms used by websites
- Potential vulnerabilities in these mechanisms
- Inherent vulnerabilities in different authentication approaches
- Typical security flaws introduced by improper implementation
- Best practices for strengthening authentication security

## Importance of Authentication Security

Authentication vulnerabilities are critical due to their direct impact on security. Attackers who exploit these weaknesses can gain unauthorized access, leading to data breaches, account takeovers, and further system compromises.

<div align="center">
  <img src="https://github.com/user-attachments/assets/5481c1ac-cbcd-4611-85ce-ccfb50697a28"></img>
</div>

## What is Authentication?

Authentication verifies the identity of a user or client attempting to access a system. Because websites are accessible to a global audience, strong authentication mechanisms are fundamental to web security.

### Types of Authentication

1. **Knowledge-based (Something You Know)**: Passwords, security questions.
2. **Possession-based (Something You Have)**: Security tokens, mobile devices.
3. **Inherence-based (Something You Are)**: Biometrics, behavioral patterns.

## Authentication vs. Authorization

- **Authentication**: Confirms the identity of a user (e.g., verifying that "Carlos123" is the account owner).
- **Authorization**: Determines what actions an authenticated user is allowed to perform (e.g., accessing sensitive data or administrative functionalities).

## How Do Authentication Vulnerabilities Arise?

Authentication vulnerabilities typically arise due to:

1. **Weak Authentication Mechanisms**: Inadequate brute-force protection, weak password policies.
2. **Implementation Flaws**: Logic errors or coding mistakes that allow bypassing authentication controls.

## Impact of Authentication Vulnerabilities

The consequences of authentication flaws can be severe, including:

- Unauthorized access to sensitive data.
- Account takeovers, leading to identity theft or financial fraud.
- Privilege escalation attacks, where attackers gain administrative control.
- Exposure of internal infrastructure and corporate systems.

## Vulnerabilities in Authentication Mechanisms

Authentication systems commonly contain distinct vulnerabilities in the following areas:

1. **Password-based login**: Susceptible to brute-force attacks and credential stuffing.
2. **Multi-factor authentication**: Weak implementation can allow bypassing security controls.
3. **Other authentication mechanisms**: May introduce flaws specific to their design.

### Vulnerabilities in Password-Based Login

Websites that use password-based authentication rely on a user-entered password as proof of identity. If an attacker can obtain or guess valid credentials, authentication security is compromised.

#### Brute-Force Attacks

A brute-force attack involves systematically guessing credentials using automated tools and predefined wordlists. Attackers exploit weak password policies and predictable user behavior to enhance their success rates.

##### Brute-Forcing Usernames

- Usernames following predictable patterns (e.g., `firstname.lastname@company.com` or `admin`) are easier to guess.
- Publicly visible usernames on profiles or error messages can aid attackers in compiling valid user lists.

##### Brute-Forcing Passwords

- Users often create weak or predictable passwords due to poor enforcement policies.
- Enforcing strong password policies is crucial, but users tend to create variations of familiar passwords, making them susceptible to attacks.

### Username Enumeration

Username enumeration occurs when attackers determine valid usernames based on website responses, making brute-force attacks more efficient.

#### Indicators of Username Enumeration:

1. **Status Codes**: During brute-force attacks, most login attempts fail, returning a consistent HTTP status code. However, if a request returns a different status code, it may indicate a valid username. Secure applications should always return uniform status codes regardless of authentication success or failure.

2. **Error Messages**: Some websites provide different error messages based on whether the username exists or if both the username and password are incorrect. To prevent information leakage, websites should use identical, generic messages for all authentication failures. Even minor inconsistencies, such as a misplaced character in an error message, can give attackers clues.

3. **Response Times**: Authentication processes should take a uniform amount of time for all requests. If the response time varies—such as taking longer when validating a correct username before checking the password—attackers can infer valid usernames. This timing discrepancy can be further amplified by inputting excessively long passwords, making delays more noticeable.

> **Note:** Ensure that Burp Suite is correctly configured and linked with your browser, as all requests will be intercepted in Burp Suite through the browser.

# Lab 1: [Username Enumeration via Different Responses](./Wpt/Server-side_topics/Authentication_vulnerabilities/Labs/Lab-1:Username_Enumeration_via_Different_Responses.md)
---

# Lab 2: [Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)

![image](https://github.com/user-attachments/assets/21cdbb53-9772-4b7f-98ed-a45dbfcd3e3f)

In this lab scenario, using the same approach as the previous lab (sorting by response length) won’t help us identify the correct username—because all the failed login responses have the same length. Instead, we need to use a keyword-based approach to grep specific error messages and filter out the correct credentials.

---

## Accessing the Lab

![image](https://github.com/user-attachments/assets/a3f22632-3357-4fe6-90c9-dc4e319607e8)

### Step 1: Click on "My Account"

After clicking on **My Account**, a login page will appear. Since we don’t have valid credentials, enter any random username and password such as `admin:admin`.

![image](https://github.com/user-attachments/assets/52342697-ac64-42ea-aba9-42323d592982)

---

## Step 2: Capture the Request in Burp Suite

1. Open **Burp Suite** and turn **Intercept On**.
2. Try logging in using the dummy credentials.

![image](https://github.com/user-attachments/assets/62d5dc7a-8567-4cf6-86b0-77599ce2fd32)

---

## Step 3: Configuring the Intruder Attack

1. Send the captured request to **Intruder**.
2. In the **Positions** tab, highlight the `username` (e.g., `admin`) and click `Add §`.

![image](https://github.com/user-attachments/assets/8bda2a19-450e-4fbc-9944-0f1dcbe9cd07)

3. Navigate to the **Payloads** tab and paste the [Username List](./Wpt/Server-side_topics/Authentication_vulnerabilities/Lab-credentials/Username-List.md).

![image](https://github.com/user-attachments/assets/fba5308f-83b0-458f-a964-c4c73c5529c1)

4. Go to the **Settings** tab and scroll down to locate **Grep - Extract**.

![image](https://github.com/user-attachments/assets/eac22607-41a3-4f1f-abd3-154dbde6958d)

5. Click `Add` to define a custom keyword.

![image](https://github.com/user-attachments/assets/3ed4fbb9-0a57-4115-ba3f-17e01f084bd6)

6. A new section will appear. Click `Fetch Response`.
7. In the **Start after expression** field, paste the following error message:

```
Invalid username or password.
```

![image](https://github.com/user-attachments/assets/8be354dc-cb50-4f9e-8b27-a7b49a4621c9)

8. It should now look like this:

![image](https://github.com/user-attachments/assets/1e85b8f4-6c19-4459-a81c-bcbb9f7d16a5)

9. Click `Start Attack`.
10. Once the attack is complete, sort the results by the `Invalid username or password.` column. The row that doesn't show this message likely contains the correct username—in our case, it’s `apple`.

![image](https://github.com/user-attachments/assets/2dd401f2-6c32-4aba-b80e-07a5ca0c9ada)

---

## Step 4: Brute-Forcing the Password

1. Send a new request to Intruder.

![image](https://github.com/user-attachments/assets/717baa9d-e917-4615-b246-1a56318fd74c)

2. In the **Positions** tab, remove the § around the username and replace it with the discovered username `apple`.
3. Add `§` around the password field instead.

![image](https://github.com/user-attachments/assets/e263c86e-c647-4aa0-bc88-e67dca583d04)

4. Navigate to the **Payloads** tab and paste the [Password List](./Wpt/Server-side_topics/Authentication_vulnerabilities/Lab-credentials/Password-List.md).

![image](https://github.com/user-attachments/assets/2016cb2c-5d39-48c4-a972-d9634ffa1ced)

5. Click `Start Attack`.

![image](https://github.com/user-attachments/assets/54575c1a-cdfa-4f3b-8f1e-fb283f918d9e)

6. We identify the password `moon`.

![image](https://github.com/user-attachments/assets/f30e5720-de43-4270-a419-9e1b71d82451)

7. Forward the successful request.

![image](https://github.com/user-attachments/assets/b30a2aff-fa21-4e14-87e1-d0074a90b6e4)

✅ We’ve successfully completed the lab!

---

 
