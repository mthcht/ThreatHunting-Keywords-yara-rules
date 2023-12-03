rule metasploit_payloads
{
    meta:
        description = "Detection patterns for the tool 'metasploit-payloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metasploit-payloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string1 = /.{0,1000}metterpreter.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
