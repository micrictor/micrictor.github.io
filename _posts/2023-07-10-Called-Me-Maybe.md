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
4. Detecting Evasions

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
mapped.

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

### MSVC vs GCC
* MSVC doesn't support inline ASM for x64
* We could just link in a masm/nasm object, but that's not as fun
* Inline assembly to set up the registers/stack with the required number of arguments.

### Experiment results

* Both systems use dynamic procedure lookup with XOR-encrypted module and procedure names to avoid basic static analysis.
* `Control` directly calls VirtalAlloc, VirtualProtect, then directly executes the shellcode
* `Main` uses ThreadpoolWork to indirectly do the same.

Significant differences in VirusTotal results - and Defender purges `control.exe` from my workstation, but not `main.exe`.

## Detection Evasions

* Included Yara rules for simple copies of the code in the repo.
* Elastic already does it - https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks

