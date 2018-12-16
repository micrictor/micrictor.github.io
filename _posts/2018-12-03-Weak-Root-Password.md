---
layout: post
title: Weak Root Password
description: CAS-003 Exam Study
categories: [ctf, firmware, wifi]
tags: [ctf, firmware, wifi, attackdefense]
---

This will be the first of many breakdowns as I go through Pentester Academy's Attack Defense CTFs. This post in particular will cover the first of four currently available firmware analysis challenges under the subcategory "WiFi Routers."

## Weak Root Password

> You've received an OpenWRT based firmware for analysis. The company assures you that the firmware is secure. You have your doubts! 

> Your mission is to recover the root password hash from the firmware and crack it! 

> All common tools used for firmware analysis and cracking are present in the lab machine.
 
Our first challenge has a very straightforward task: Recover the root password hash and crack it.

Upon entering the box, you have two files in your home directory:
```
student@attackdefense:~$ ls -l
total 12172
-rw-r--r-- 1 root root 8529147 Sep 25 19:02 1000000-password-seclists.txt
-rw-r--r-- 1 root root 3932160 Sep 25 19:02 firmware.bin
student@attackdefense:~$ file 1000000-password-seclists.txt
1000000-password-seclists.txt: ASCII text
student@attackdefense:~$ file firmware.bin
firmware.bin: data
student@attackdefense:~$
```

Given the initial statement, we should have binwalk on the box, so we'll use it to unpack the firmware.
```
student@attackdefense:~$ binwalk -bve firmware.bin

Scan Time:     2018-12-02 14:20:08
Target File:   /home/student/firmware.bin
MD5 Checksum:  b6d94b222813fa93502c26e398f97895
Signatures:    344

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
512           0x200           LZMA compressed data, properties: 0x6D, dictionary size: 8388608 bytes, uncompressed size: 3517868 bytes
1159648       0x11B1E0        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 2324164 bytes, 1024 inodes, blocksize: 262144 bytes, created: 2018-09-25 17:11:46
1159758       0x11B24E        xz compressed data
1315378       0x141232        xz compressed data
1331274       0x14504A        xz compressed data
1416462       0x159D0E        xz compressed data
1499950       0x16E32E        xz compressed data
....
```

Looks like there's one sqaushfs filesystem, we'll go ahead and look at the shadow file stored in it.

```
student@attackdefense:~$ head ~/_firmware.bin.extracted/squashfs-root/etc/shadow
root:$6$d6oAYJZc$BVECjh88noC0ZRIxNiuNL2LDXBnMzMQS.AzbpTd3vkFC3yQS8ytad7oifCjt4M2RSA3DMhxpg8xTOpawPtCCF/:17799:0:99999:7:::
daemon:*:17751:0:99999:7:::
bin:*:17751:0:99999:7:::
sys:*:17751:0:99999:7:::
sync:*:17751:0:99999:7:::
games:*:17751:0:99999:7:::
man:*:17751:0:99999:7:::
lp:*:17751:0:99999:7:::
mail:*:17751:0:99999:7:::
news:*:17751:0:99999:7:::
student@attackdefense:~$
```

Now that we have the root password hash, we need to crack it. I don't know, offhand, what type of hash "$6$" is, so I went to [hashcat's example hashes list](https://hashcat.net/wiki/doku.php?id=example_hashes), which states that our hash is a SHA512crypt hash, which is mode 1800 on hashcat. After putting the hash inside hashes.txt, I ran hashcat on our hash using the supplied passwordlist. In about 1.5 minutes, we cracked the hash.

```
$6$d6oAYJZc$BVECjh88noC0ZRIxNiuNL2LDXBnMzMQS.AzbpTd3vkFC3yQS8ytad7oifCjt4M2RSA3DMhxpg8xTOpawPtCCF/:q1w2e3r4
```


