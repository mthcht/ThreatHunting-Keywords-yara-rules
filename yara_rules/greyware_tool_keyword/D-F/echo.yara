rule echo
{
    meta:
        description = "Detection patterns for the tool 'echo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account.
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string1 = /.{0,1000}\%COMSPEC\%.{0,1000}echo.{0,1000}\\pipe\\.{0,1000}/ nocase ascii wide
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string2 = /.{0,1000}cmd.{0,1000}echo.{0,1000}\\pipe\\.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to test echo command after exploitation
        // Reference: N/A
        $string3 = /.{0,1000}cmd\.exe\s\s\/S\s\/D\s\/c.{0,1000}\secho\s123/ nocase ascii wide
        // Description: alternative to whoami
        // Reference: N/A
        $string4 = /.{0,1000}cmd\.exe\s\/c\secho\s\%username\%.{0,1000}/ nocase ascii wide
        // Description: Named pipe impersonation
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string5 = /.{0,1000}cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
