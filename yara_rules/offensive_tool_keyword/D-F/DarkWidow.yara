rule DarkWidow
{
    meta:
        description = "Detection patterns for the tool 'DarkWidow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DarkWidow"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string1 = /\s\<PPID\sto\sspoof\>\\n\\n/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string2 = /\sblindeventlog\.exe/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string3 = /\/blindeventlog\.exe/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string4 = /\/DarkWidow\.git/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string5 = /\[\!\]\sFailed\sto\sKill\sEventLog\sService/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string6 = /\[\+\]\sEvent\sLogger\sis\sEither\sNOT\srunning\sor\sAlready\sKilled\sPreviously\!/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string7 = /\[\+\]\sReady\sfor\sPost\-Exp\s\:\)/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string8 = /\\blindeventlog\.exe/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string9 = /\\DarkWidow\\src\\/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string10 = /\\Running_msf_revshell/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string11 = /\\x64\\Release\\indirect\.exe\s/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string12 = /\]\sKilling\sEventLog\sThreads\s\(if\srunning\)/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string13 = /\]\sShellcode\sDecryption\sStarted/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string14 = /\=\=\=\=\=\=\=\=\=\=\=\sHavoc\sand\smsf\srevshell\s\=\=\=\=\=\=\=\=/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string15 = /4D1B765D\-1287\-45B1\-AEDC\-C4B96CF5CAA2/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string16 = /6C9CF6A0\-C098\-4341\-8DD1\-2FCBA9594067/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string17 = /DarkWidow\-main/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string18 = /reveng007\/DarkWidow/ nocase ascii wide

    condition:
        any of them
}
