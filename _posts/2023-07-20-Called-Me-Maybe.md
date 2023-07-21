---
layout: post
title: Called Me Maybe - EDR Evasion
---

Endpoint Detection and Response (EDR) solutions have started to collect and analyze
the chain of functions leading up to the execution of certain Windows API
functions, also known as the call stack. This post will look into the data
available to EDRs, and examine one technique used by malware to avoid it. 

I had originally hoped to talk about this at [Hexacon 2023](https://hexacon.fr),
but they had a bunch of extremely talented people apply to talk and I didn't
make the final cut. If you're looking for a conference with a focus on offensive
security, conveniently co-scheduled with the Rugby World Cup, you should go!

## Contents

1. [EDR Call Stack Analysis](#edr-call-stack-analysis)
2. [Seeing What EDR Sees](#seeing-what-edr-sees)
3. [Using Callbacks to Fake Call Stacks](#using-callbacks-to-fake-call-stacks)
4. [Detection](#detection)

## EDR Call Stack Analysis

Endpoint Detection and Response (EDR) tools commonly analyze the list of
procedures preceding calls to Win32 APIs that are commonly used by malware.
Examples include, but are not limited to:
* VirtualAlloc
* VirtualProtect
* CreateRemoteThread
* WriteProcessMemory

The call stacks are collected one of two major ways
1. Collection of the stack frames at call time by hooking the targeted APIs,
either in user space or kernel space.
2. Direct receipt of the call stack from external monitoring tools, such as
Event Tracing for Windows (ETW) Threat Intelligence providers or Sysmon.

The outputs of the initial collection may be virtual addresses within the
source process memory. The EDR tool may then resolve these addresses to derive
information about the procedures in the stack, such as:
* The image they're within (e.g. the executable image, a loaded DLL).
* The name of the symbol (function name), if known.
* The mapping of the page the address is in (`.text` section, stack, heap).

In short, some EDRs will get the list of procedures that led up to an API call
of interest. For each of the procedures, they may try to determine what image
the procedure was from, what the symbol name is, and where in memory it is
mapped. Analysis of that information can be used to identify when unusual or
unexpected procedures are invoking APIs commonly used by malware, which in turn
can help classify running software as malicious.

## Seeing What EDR Sees

To avoid detection, it would be massively helpful to be able to view the same
data available to EDRs. Two main methods are likely used to get this data:
*   Subscribing to the Event Tracing for Windows (ETW) Threat Intelligence (TI)
    provider.
*   Hooking the API methods, in either user or kernel space

SysMon also provides CreateRemoteThread call stacks for analysis, and, because
I didn't need to be able to do this at scale, I was able to manually validate
call stacks in my debugger. 

## Using Callbacks to Fake Call Stacks

The Windows API includes a large number of functions that are designed to work
asynchronously, but are called synchronously. To do so, they expect the caller
to provide a callback function as a parameter. If we want to make it look like
a target API call originated from a trusted memory region - say, a procedure in
ntdll.dll - this is great news.

By having our "callback" function manually set up parameters, according to the
x64 calling convention, then jump to the target API, we can call any target API
we want. The one caveat to this is that a callback function cannot call a
target API with more arguments than itself.

As a quick note, you may notice that I used GCC for everything instead of MSVC.
Well, it turns out the MSVC doesn't support inline 64-bit assembly. I could
have just written and assembled the hand-written stuff in a separate object,
then link it into the final program, but that didn't sound as fun.

The "magic" that sets up the parameters and jumps to the target API can be
found [here](https://github.com/micrictor/windows-api-proxy/blob/hexacon/thunk.h).

### Experiment

To prove the merit of the callback technique to avoid detection, I created a
control executable and a main executable, which load and invoke the same
payload, spawning `calc.exe`. The only difference between them is that the
main executable makes the VirtualAlloc and VirtualProtect calls using callback
redirection.

To prevent antivirus solutions from doing static detections, both samples use
the same an XOR OTP key to encrypt function names and module names. Those names
are then used to dynamically resolve symbol names using `GetProcAddress`.

[The control, without callback redirection,](https://www.virustotal.com/gui/file/99bcdbde638353fa59f2ce91c0ff7c27f7c2d5cbaf3f2cb720920f436316b8f4?nocache=1)
had 17/71 detections when initially uploaded. It has increased to 45/71 at time
of publishing. Windows Defender also detects this and keeps deleting it from my
hard drive.

[The main, with callback redirection,](https://www.virustotal.com/gui/file/f2f44f72fd1f12bf184327e1a9a79e65eb8b100146ccbe73749f41a41084fbd2?nocache=1)
had 5/71 detections when initially uploaded, and only 6/71 at time of
publishing.

[The full source code for both the control and "main" executables are available on GitHub](https://github.com/micrictor/windows-api-proxy/tree/hexacon).

## Detection

Included in the GitHub repository are [Yara rules](https://github.com/micrictor/windows-api-proxy/tree/hexacon/detections).
These rules are specific to the code in the repository, and don't generalize
well to the overall technique.

Detection can be based on the use of known Windows API methods that support
callbacks. Many of these methods are already known to be "suspicious", due to
their use to indirectly invoke shellcode. GitHub user
[aahmad097](https://github.com/aahmad097) maintains
[a repository containing a long list of such methods](https://github.com/aahmad097/AlternativeShellcodeExec),
including examples of how they can be used.

If the full stack frame is available for analysis, likely via an API hook, I
believe the use of callbacks to directly call APIs can be identified for 64-bit
programs thanks to the ["home space"](https://learn.microsoft.com/en-us/archive/blogs/ntdebugging/challenges-of-debugging-optimized-x64-code)/["shadow space"](https://masm32.com/board/index.php?topic=9227.0).
I haven't yet taken the time to prove out the technique, but small scale
testing in a debugger has let me identify when a caller to a windows API has
modified the home space in a way that's not consistent with the x64 calling
convention, indicated handwritten assembly. Specifically, by knowing what
acceptable values for the four preserved registers - rbx, rbp, rsi, and rdi -
are for the the "caller" according to the stack frame, you can determine if
the values currently in the corresponding positions in the home space have
been directly modified.

If you're looking for further reading, Elastic Security recently published a
blog post about their callstack based detections, including the fact that they
attempt to detect when callbacks are used to avoid it. This can be found at
https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks

