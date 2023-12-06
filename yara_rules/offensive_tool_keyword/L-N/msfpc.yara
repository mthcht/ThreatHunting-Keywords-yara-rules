rule msfpc
{
    meta:
        description = "Detection patterns for the tool 'msfpc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msfpc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/g0tmi1k/msfpc
        $string1 = /\/msfpc\.sh/ nocase ascii wide
        // Description: A quick way to generate various basic Meterpreter payloads via msfvenom (part of the Metasploit framework)
        // Reference: https://github.com/g0tmi1k/msfpc
        $string2 = /msfpc\.sh/ nocase ascii wide

    condition:
        any of them
}
