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
        // Description: potential malleable Cobalt Strike profiles behavior
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string5 = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
        // Description: Named pipe impersonation
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string6 = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
        // Description: covering history tracks on linux system
        // Reference: https://rosesecurity.gitbook.io/red-teaming-ttps/linux
        $string7 = /echo\s\'\'\'\'\s\-\/\.bash\shistory/
        // Description: delete bash history
        // Reference: N/A
        $string8 = /echo\s\'\'\s\>\s\~\/\.bash_history/
        // Description: covering history tracks on linux system
        // Reference: https://rosesecurity.gitbook.io/red-teaming-ttps/linux
        $string9 = /echo\s\\"\\"\s\>\s\/var\/log\/auth\.log\s/
        // Description: clearing logs to cover traces
        // Reference: N/A
        $string10 = "echo \"\" > /var/log/cron"
        // Description: clearing logs to cover traces
        // Reference: N/A
        $string11 = "echo \"\" > /var/log/secure"
        // Description: clearing logs to cover traces
        // Reference: N/A
        $string12 = "echo \"\" > /var/log/wtmp"
        // Description: clearing logs to cover traces
        // Reference: N/A
        $string13 = "echo \"\" > /var/spool/mail/root"
        // Description: writing an ASPX file to C:\inetpub\wwwroot\ (potential Web shell deployment)
        // Reference: N/A
        $string14 = /echo\s\>\sC\:\\inetpub\\wwwroot\\.{0,1000}\\.{0,1000}\.aspx/ nocase ascii wide
        // Description: This command disables kprobes by writing '0' to the enabled file. Kprobes are dynamic breakpoints in the Linux kernel that can be used to intercept functions and gather information for debugging or monitoring.
        // Reference: N/A
        $string15 = "echo 0 > /sys/kernel/debug/kprobes/enabled"
        // Description: This command turns off tracing for a specific instance
        // Reference: N/A
        $string16 = /echo\s0\s\>\s\/sys\/kernel\/debug\/tracing\/instances\/\$.{0,1000}\/tracing_on/
        // Description: clearing logs to cover traces
        // Reference: N/A
        $string17 = "echo 0 > /var/log/cron"
        // Description: clearing logs to cover traces
        // Reference: N/A
        $string18 = "echo 0 > /var/log/secure"
        // Description: clearing logs to cover traces
        // Reference: N/A
        $string19 = "echo 0 > /var/log/wtmp"
        // Description: clearing logs to cover traces
        // Reference: N/A
        $string20 = "echo 0 > /var/spool/mail/root"
        // Description: linux command abused by attacker
        // Reference: N/A
        $string21 = /echo\s\'set\s\+o\shistory\'\s\>\>\s\/etc\/profile/

    condition:
        any of them
}
