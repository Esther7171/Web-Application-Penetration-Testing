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

# Lab 1: [Username Enumeration via Different Responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)

In this lab scenario, we have a provided [Username List](./Wpt/Server-side_topics/Authentication_vulnerabilities/Lab-credentials/Username-List.md) and [Password List](./Wpt/Server-side_topics/Authentication_vulnerabilities/Lab-credentials/Password-List.md). The website is vulnerable to brute-force attacks.

![image](https://github.com/user-attachments/assets/3e8cb5ca-e709-4af1-9566-5ad0719a2c1b)

### Accessing the Lab

#### Step 1: Click on "My Account"

![image](https://github.com/user-attachments/assets/25229db9-e1ea-4b36-8969-fe769b8a1615)

After clicking on "My Account," a login page will appear. Since we don’t have valid credentials, enter any random username and password, such as `admin:admin`.

![image](https://github.com/user-attachments/assets/60884e42-af92-41c3-a3a1-87cbf3e170d4)

#### Step 2: Capture the Request in Burp Suite

1. Open Burp Suite and turn **Intercept On**.
2. Attempt to log in with the credentials entered in the previous step.

![image](https://github.com/user-attachments/assets/ef62c86d-59c0-4da0-9bc9-61883563097e)

3. Once the request is captured, click on `Action` and select `Send to Intruder`.

![image](https://github.com/user-attachments/assets/91b02aed-24da-4267-9ceb-15620e4f9c34)

#### Step 3: Configuring the Intruder Attack

1. In the **Intruder** tab, select the username `admin` and click `Add §` to mark it as an attack position.

![image](https://github.com/user-attachments/assets/a28c87c3-58c4-47f0-b49c-323efb4e990d)

The marked position should appear as follows:

![image](https://github.com/user-attachments/assets/e5882c48-91c6-48c1-95a0-11abdc83ed3d)

2. Navigate to the **Payloads** tab, copy the [Username List](./Wpt/Server-side_topics/Authentication_vulnerabilities/Lab-credentials/Username-List.md), and paste it into the payload settings column by clicking on `Paste`.

![image](https://github.com/user-attachments/assets/4146e469-9a04-4dfc-b945-d552a37a64f6)

#### Step 4: Start the Attack

Click `Start Attack` to begin brute-forcing the usernames.

![image](https://github.com/user-attachments/assets/b42ca8a9-d6e6-4ec5-923d-5a1507e7703a)

#### Step 5: Identifying the Valid Username

1. Click on the **Length** column to sort results.
2. Identify any response with a longer length than others.
3. Compare the response to this payload with other responses. If other responses say `Invalid username` while this response says `Incorrect password`, the username is valid.

Once the correct username is identified, proceed to brute-force the password.

#### Step 6: Brute-Forcing the Password

1. Close the attack and return to the **Intruder** tab.
2. Go to the **Positions** tab, click `Clear §`, and replace the username with the valid one identified earlier.
3. Add a payload position to the password field. The request should now look like this:

![image](https://github.com/user-attachments/assets/3fa0ded8-150e-42fc-a80d-81534273d387)

4. In the **Payloads** tab, click `Clear` to remove the previous wordlist.

![image](https://github.com/user-attachments/assets/b14236a6-5625-486c-a777-48c389ee2246)

5. Paste the [Password List](./Wpt/Server-side_topics/Authentication_vulnerabilities/Lab-credentials/Password-List.md).

![image](https://github.com/user-attachments/assets/4e0b64bc-923a-43c6-a078-b716edfb2a5a)

6. Click `Start Attack` to begin brute-forcing the password.

![image](https://github.com/user-attachments/assets/1ee0047f-f906-4399-aa57-fc10404f37d4)

#### Step 7: Identifying the Correct Password

1. Sort results by **Length**.
2. The valid password will correspond to a `302 Found` status code.

#### Step 8: Logging in with the Identified Credentials

Use the discovered username and password to log in.

![image](https://github.com/user-attachments/assets/f68d9cfb-c124-4b57-b8e6-ca5139ef9a49)

We have successfully completed the lab!

---

# Lab 2: [Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)

![image](https://github.com/user-attachments/assets/21cdbb53-9772-4b7f-98ed-a45dbfcd3e3f)

In This lab scenario If we repeat the same process as last lab We simply couldn’t find the correct username bez there are multiple names showing same length.In this lab we need to add a keyword or a error message and grep all the request and check the right username and password that didnt show that error message. 

## Accessing the Lab

![image](https://github.com/user-attachments/assets/a3f22632-3357-4fe6-90c9-dc4e319607e8)

#### Step 1: Click on "My Account"

After clicking on "My Account," a login page will appear. Since we don’t have valid credentials, enter any random username and password, such as admin:admin.

![image](https://github.com/user-attachments/assets/52342697-ac64-42ea-aba9-42323d592982)

#### Step 2: Capture the Request in Burp Suite

1. Open Burp Suite and turn **Intercept On**.
2. Attempt to log in with the credentials entered in the previous step.

![image](https://github.com/user-attachments/assets/62d5dc7a-8567-4cf6-86b0-77599ce2fd32)

#### Step 3: Configuring the Intruder Attack

1. Send this request to Intruder, In the **Intruder** tab, select the username `admin` and click `Add §` to mark it as an attack position.

![image](https://github.com/user-attachments/assets/8bda2a19-450e-4fbc-9944-0f1dcbe9cd07)

2. Navigate to the **Payloads** tab, copy the [Username List](./Wpt/Server-side_topics/Authentication_vulnerabilities/Lab-credentials/Username-List.md), and paste it into the payload settings column by clicking on `Paste`.

![image](https://github.com/user-attachments/assets/fba5308f-83b0-458f-a964-c4c73c5529c1)

3. After adding the username list go to Setting tab
4. In setting tab scroll down and look for `Grep - Extract`

![image](https://github.com/user-attachments/assets/eac22607-41a3-4f1f-abd3-154dbde6958d)

5. Click on add

![image](https://github.com/user-attachments/assets/3ed4fbb9-0a57-4115-ba3f-17e01f084bd6)
  
6. A New tab will appear, If Click on `featch Response` you will get response of your request
7. We need to past this error message , In `Start after expression:` just past the below error message.
```
Invalid username or password.
```

![image](https://github.com/user-attachments/assets/8be354dc-cb50-4f9e-8b27-a7b49a4621c9)

8. It should look lik this:

![image](https://github.com/user-attachments/assets/1e85b8f4-6c19-4459-a81c-bcbb9f7d16a5)

9. Just Start Attack
10. When you sort `Invalid username or password.` column, we got our username `apple`

![image](https://github.com/user-attachments/assets/2dd401f2-6c32-4aba-b80e-07a5ca0c9ada)

11. Send this new Request to Intruder.

![image](https://github.com/user-attachments/assets/717baa9d-e917-4615-b246-1a56318fd74c)

12. Remember that keyword we added to find username we no longer need that if u add that keyword in password it didn’t work.
13. As we know the username `add §` at password position

![image](https://github.com/user-attachments/assets/e263c86e-c647-4aa0-bc88-e67dca583d04)

14. Now Paste the [Password List](./Wpt/Server-side_topics/Authentication_vulnerabilities/Lab-credentials/Password-List.md).

![image](https://github.com/user-attachments/assets/2016cb2c-5d39-48c4-a972-d9634ffa1ced)

15. And `Start Attack`

 ![image](https://github.com/user-attachments/assets/54575c1a-cdfa-4f3b-8f1e-fb283f918d9e)

16. We got the password `moon`

![image](https://github.com/user-attachments/assets/f30e5720-de43-4270-a419-9e1b71d82451)

17. Forward this Request.

![image](https://github.com/user-attachments/assets/b30a2aff-fa21-4e14-87e1-d0074a90b6e4)

We have successfully completed the lab!
---
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

---

## ✅ Lab Completed

We’ve successfully bypassed authentication by grepping the error message and filtering out the valid username and password!


 
