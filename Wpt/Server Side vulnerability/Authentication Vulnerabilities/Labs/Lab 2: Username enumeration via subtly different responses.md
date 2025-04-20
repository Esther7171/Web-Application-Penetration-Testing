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
