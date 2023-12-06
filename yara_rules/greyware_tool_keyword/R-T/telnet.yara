rule telnet
{
    meta:
        description = "Detection patterns for the tool 'telnet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telnet"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious shell commands used in various Equation Group scripts and tools
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_apt_equationgroup_lnx.yml
        $string1 = /\&\&\stelnet\s.{0,1000}\s2\>\&1\s\<\/dev\/console/ nocase ascii wide
        // Description: telnet reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string2 = /telnet\s.{0,1000}\s\|\s\/bin\/bash\s\|\stelnet\s/ nocase ascii wide

    condition:
        any of them
}
