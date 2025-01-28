rule psexec
{
    meta:
        description = "Detection patterns for the tool 'psexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psexec"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling Lateral Movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string1 = /\s\-accepteula\s\-nobanner\s\-d\scmd\.exe\s\/c\s/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string2 = /\.exe\s\/i\s\/s\scmd\s/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string3 = /\.exe\s\/i\s\/s\scmd\.exe/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string4 = /\.exe\s\/i\s\/s\spowershell/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string5 = /\.exe\s\/i\s\/s\spwsh/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string6 = /\.exe\s\/s\s\/i\scmd\.exe/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string7 = /\.exe\s\/s\s\/i\spowershell/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string8 = /\.exe\s\/s\s\/i\spwsh/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string9 = /\.exe\s\-i\s\-s\scmd\s/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string10 = /\.exe\s\-i\s\-s\scmd\s/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string11 = /\.exe\s\-i\s\-s\scmd\.exe/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string12 = /\.exe\s\-i\s\-s\spowershell/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string13 = /\.exe\s\-i\s\-s\spwsh/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string14 = /\.exe\s\-s\s\-i\scmd\.exe/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string15 = /\.exe\s\-s\s\-i\spowershell/ nocase ascii wide
        // Description: privilege escalation to local system with psexec
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string16 = /\.exe\s\-s\s\-i\spwsh/ nocase ascii wide
        // Description: PsExec is a legitimate Microsoft tool for remote administration. However. attackers can misuse it to execute malicious commands or software on other network machines. install persistent threats. and evade some security systems. 
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string17 = /\\PsExec\.exe/ nocase ascii wide
        // Description: PsExec is a legitimate Microsoft tool for remote administration. However. attackers can misuse it to execute malicious commands or software on other network machines. install persistent threats. and evade some security systems. 
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string18 = /\\SOFTWARE\\Sysinternals\\PsExec\\EulaAccepted/ nocase ascii wide
        // Description: PsExec is a legitimate Microsoft tool for remote administration. However. attackers can misuse it to execute malicious commands or software on other network machines. install persistent threats. and evade some security systems. 
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string19 = /\\Windows\\Prefetch\\PSEXEC/ nocase ascii wide
        // Description: .key file created and deleted on the target system
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string20 = /\\Windows\\PSEXEC\-.{0,100}\.key/ nocase ascii wide
        // Description: .key file created and deleted on the target system
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string21 = /PSEXEC\-.{0,100}\.key/ nocase ascii wide
        // Description: PsExec is a legitimate Microsoft tool for remote administration. However. attackers can misuse it to execute malicious commands or software on other network machines. install persistent threats. and evade some security systems. 
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string22 = /PsExec\.exe\s\/accepteula/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling Lateral Movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string23 = /PsExec\[1\]\.exe/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling Lateral Movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string24 = /PsExec64\.exe/ nocase ascii wide
        // Description: PsExec is a legitimate Microsoft tool for remote administration. However. attackers can misuse it to execute malicious commands or software on other network machines. install persistent threats. and evade some security systems. 
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string25 = "PSEXECSVC" nocase ascii wide
        // Description: prefetch - .key file created and deleted on the target system
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string26 = /PSEXECSVC\.EXE\-.{0,100}\.pf/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
