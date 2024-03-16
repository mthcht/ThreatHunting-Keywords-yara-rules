rule stowaway
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string1 = /\/linux_x64_admin/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string2 = /\/linux_x64_agent/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string3 = /\/linux_x86_admin/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string4 = /\/linux_x86_agent/ nocase ascii wide

    condition:
        any of them
}
