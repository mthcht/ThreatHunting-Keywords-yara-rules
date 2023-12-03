rule SplunkWhisperer2
{
    meta:
        description = "Detection patterns for the tool 'SplunkWhisperer2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SplunkWhisperer2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string1 = /.{0,1000}\s\-\-payload\-file\spwn\.bat.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string2 = /.{0,1000}\s\-\-UserName\s.{0,1000}\s\-\-Password\s.{0,1000}\s\-\-Payload\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string3 = /.{0,1000}\/splunk_whisperer\.git.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string4 = /.{0,1000}\/SplunkWhisperer2\.git.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string5 = /.{0,1000}airman604\/splunk_whisperer.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string6 = /.{0,1000}cnotin\/SplunkWhisperer2.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string7 = /.{0,1000}PySplunkWhisperer2.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string8 = /.{0,1000}SharpSplunkWhisperer2.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string9 = /.{0,1000}splunk_whisperer\.py.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string10 = /.{0,1000}splunk_whisperer\-master.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation or remote code execution through Splunk Universal Forwarder (UF) misconfigurations
        // Reference: https://github.com/cnotin/SplunkWhisperer2
        $string11 = /.{0,1000}SplunkWhisperer2\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
