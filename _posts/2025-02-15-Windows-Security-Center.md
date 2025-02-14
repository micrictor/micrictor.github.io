---
layout: post
title: "Windows Security Center (WSC) DoS"
date: 2025-02-15
categories: [Security, Vulnerabilities, Windows]
tags: [DoS, Windows Security Center, Vulnerability]
published: false
---

This post examines a denial of service, by way of memory exhaustion,
vulnerability in the Microsoft Windows Security Center. The attack leads to
noticeable degradation in a couple user-facing security features, including
status reporting of antimalware and firewall products and the ability to start
an on-demand scan.

## Overview

While poking around at on-by-default ALPC services in Microsoft Windows 11, I
noticed that the Windows Security Center service (WSCSVC) is vulnerable to a
denial of service attack. The service is responsible for monitoring the status
of various security products on the system, as well as handling events like the
registration of new security products. It is this event handling system that
ends up permitting unprivileged users to exhaust the memory of the service, and
therefore the system, resulting in a denial of service condition.

The service is implemented as a
svchost.exe service that runs as SYSTEM in a Protected Process Light (PPL).

## Outline

1. Introduction
    - Brief explanation of denial of service (DoS) attacks
    - Importance of the Windows Security Center service

2. Vulnerability Details
    - Description of the vulnerability
    - Affected versions of Windows
    - Potential impact on systems

3. Exploitation
    - How the vulnerability can be exploited
    - Example scenarios of exploitation

4. Mitigation and Protection
    - Steps to mitigate the vulnerability
    - Best practices for securing Windows systems

5. Conclusion
    - Summary of key points
    - Importance of staying updated with security patches
