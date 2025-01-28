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
        $string20 = /\\Windows\\PSEXEC\-.{0,1000}\.key/ nocase ascii wide
        // Description: .key file created and deleted on the target system
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string21 = /PSEXEC\-.{0,1000}\.key/ nocase ascii wide
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
        $string26 = /PSEXECSVC\.EXE\-.{0,1000}\.pf/ nocase ascii wide

    condition:
        any of them
}
