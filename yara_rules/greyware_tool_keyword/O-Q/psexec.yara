rule psexec
{
    meta:
        description = "Detection patterns for the tool 'psexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psexec"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string1 = /.{0,1000}\s\-accepteula\s\-nobanner\s\-d\scmd\.exe\s\/c\s.{0,1000}/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string2 = /.{0,1000}\.exe\s\-i\s\-s\scmd\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string3 = /.{0,1000}\\PsExec\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string4 = /.{0,1000}\\Windows\\Prefetch\\PSEXEC.{0,1000}/ nocase ascii wide
        // Description: .key file created and deleted on the target system
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string5 = /.{0,1000}PSEXEC\-.{0,1000}\.key.{0,1000}/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string6 = /.{0,1000}PsExec\[1\]\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string7 = /.{0,1000}PsExec64\.exe.{0,1000}/ nocase ascii wide
        // Description: PsExec is a legitimate Microsoft tool for remote administration. However. attackers can misuse it to execute malicious commands or software on other network machines. install persistent threats. and evade some security systems. 
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string8 = /.{0,1000}PSEXECSVC.{0,1000}/ nocase ascii wide
        // Description: .key file created and deleted on the target system
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string9 = /.{0,1000}PSEXECSVC\.EXE\-.{0,1000}\.pf.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
