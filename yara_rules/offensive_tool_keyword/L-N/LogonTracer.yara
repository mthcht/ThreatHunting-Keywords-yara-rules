rule LogonTracer
{
    meta:
        description = "Detection patterns for the tool 'LogonTracer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LogonTracer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LogonTracer is a tool to investigate malicious logon by visualizing and analyzing Windows Active Directory event logs. This tool associates a host name (or an IP address) and account name found in logon-related events and displays it as a graph. This way. it is possible to see in which account login attempt occurs and which host is used.
        // Reference: https://github.com/JPCERTCC/LogonTracer
        $string1 = /LogonTracer/ nocase ascii wide

    condition:
        any of them
}
