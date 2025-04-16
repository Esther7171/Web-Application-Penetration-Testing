# How to preform a Vulnerability Assesment Step by step

1. Authentication


For white box testing of an authentication page.

1. user account
2. Example i have a account `Esther` and password is `Admin@123`.
3. I will create a wordlist  2 differnty 1 for user and 2nd for password ,like about 10 words that dosn't make more load on server. and include your username and passowd either on 6th postion or 8th postion.

In first case use Sniper attack at `username` field to check, even if the password is Invalde the login page authorising the username by any differece in `length`, `response time`. 










Bug bounty

Dos attacks on site
1. profile picture upload
  * this is lotta pixel image just upload it to profile picture and open the uploded image in new tab if it hang or buffer than its a bug.
2. string method
  * upload long strings on any input field after uploading strings if website buffer it mean its a bug
3. wordpress `xmlrpc`: if it enable u getting ping back comming that mean it can do dos
4. no rate limit



 403 Access denied bypass

 try this
 ```
https://github.com/iamj0ker/bypass-403
```
