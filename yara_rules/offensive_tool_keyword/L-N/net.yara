rule net
{
    meta:
        description = "Detection patterns for the tool 'net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "net"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Conti Ransomware Proxyshell PowerShell command #9
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string1 = /net\sgroup\s.{0,1000}domain\sadmins.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}
