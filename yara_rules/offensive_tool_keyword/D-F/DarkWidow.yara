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
        $string1 = /\sblindeventlog\.exe/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string2 = /\/blindeventlog\.exe/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string3 = /\/DarkWidow\.git/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string4 = /\\blindeventlog\.exe/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string5 = /\\x64\\Release\\indirect\.exe\s/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string6 = /4D1B765D\-1287\-45B1\-AEDC\-C4B96CF5CAA2/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string7 = /DarkWidow\-main/ nocase ascii wide
        // Description: Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // Reference: https://github.com/reveng007/DarkWidow
        $string8 = /reveng007\/DarkWidow/ nocase ascii wide

    condition:
        any of them
}
