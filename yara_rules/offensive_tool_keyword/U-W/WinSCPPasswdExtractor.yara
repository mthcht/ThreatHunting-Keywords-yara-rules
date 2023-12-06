rule WinSCPPasswdExtractor
{
    meta:
        description = "Detection patterns for the tool 'WinSCPPasswdExtractor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinSCPPasswdExtractor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Extract WinSCP Credentials from any Windows System or winscp config file
        // Reference: https://github.com/NeffIsBack/WinSCPPasswdExtractor
        $string1 = /WinSCPPasswdExtractor/ nocase ascii wide

    condition:
        any of them
}
