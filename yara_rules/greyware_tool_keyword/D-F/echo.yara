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
        $string1 = /\%COMSPEC\%.{0,1000}echo.{0,1000}\\pipe\\/ nocase ascii wide
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string2 = /cmd.{0,1000}echo.{0,1000}\\pipe\\/ nocase ascii wide
        // Description: Adversaries may attempt to test echo command after exploitation
        // Reference: N/A
        $string3 = /cmd\.exe\s\s\/S\s\/D\s\/c.{0,1000}\secho\s123/ nocase ascii wide
        // Description: alternative to whoami
        // Reference: N/A
        $string4 = /cmd\.exe\s\/c\secho\s\%username\%/ nocase ascii wide
        // Description: Named pipe impersonation
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string5 = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
        // Description: delete bash history
        // Reference: N/A
        $string6 = /echo\s\'\'\s\>\s\~\/\.bash_history/ nocase ascii wide
        // Description: This command disables kprobes by writing '0' to the enabled file. Kprobes are dynamic breakpoints in the Linux kernel that can be used to intercept functions and gather information for debugging or monitoring.
        // Reference: N/A
        $string7 = /echo\s0\s\>\s\/sys\/kernel\/debug\/kprobes\/enabled/ nocase ascii wide
        // Description: This command turns off tracing for a specific instance
        // Reference: N/A
        $string8 = /echo\s0\s\>\s\/sys\/kernel\/debug\/tracing\/instances\/\$.{0,1000}\/tracing_on/ nocase ascii wide
        // Description: linux command abused by attacker
        // Reference: N/A
        $string9 = /echo\s\'set\s\+o\shistory\'\s\>\>\s\/etc\/profile/ nocase ascii wide

    condition:
        any of them
}
