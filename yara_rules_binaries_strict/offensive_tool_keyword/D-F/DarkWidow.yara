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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
