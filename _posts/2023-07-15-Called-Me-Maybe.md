---
layout: post
title: Called Me Maybe - EDR Evasion
published: false
---

Endpoint Detection and Response (EDR) solutions have started to collect and analyze
the chain of functions leading up to the execution of certain Windows API
functions, also known as the call stack. This post will look into the data
available to EDRs, and examine one technique used by malware to avoid it. 

I had originally hoped to talk about this at [Hexacon 2023](https://hexacon.fr),
but they had a bunch of extremely talented people apply to talk and I didn't
make the final cut. If you're looking for a conference with a focus on offensive
security, conveniently co-scheduled with the Rugby World Cup, you should go!

https://docs.google.com/presentation/d/1JLPq_Ypkp0auTwpflXJ_qT3U7CKXQNQ_oT8Q53hgNiE/edit?pli=1&resourcekey=0-oB20j8fvPa8VZpfkW0Geqg#slide=id.g21ee16f8bbc_0_1 


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

1. ETW - Sealight and PPLRunner 
2. Sysmon event ID 10 (CreateRemoteThread)
3. API Hooking
4. Manually (debugger + stack frame analysis)


## Using Callbacks to Fake Call Stacks

* Some Win32 APIs have callback functions
* Some are more direct (InvokeOnceExecuteOnce, ThreadpoolWork), while others are less direct (FlsAlloc deallocation callbacks)
* We can use them to call target APIs without including our
own memory in the call stack.

[The full source code for both the control and "main" executables are available on GitHub](https://github.com/micrictor/windows-api-proxy/tree/hexacon)

### MSVC vs GCC
* MSVC doesn't support inline ASM for x64
* We could just link in a masm/nasm object, but that's not as fun
* Inline assembly to set up the registers/stack with the required number of arguments.

### Experiment results

* Both systems use dynamic procedure lookup with XOR-encrypted module and procedure names to avoid basic static analysis.
* `Control` directly calls VirtalAlloc, VirtualProtect, then directly executes the shellcode
* `Main` uses ThreadpoolWork to indirectly do the same.

Significant differences in VirusTotal results - and Defender purges `control.exe` from my workstation, but not `main.exe`.

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

