rule PSRecon
{
    meta:
        description = "Detection patterns for the tool 'PSRecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSRecon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PSRecon gathers data from a remote Windows host using PowerShell (v2 or later). organizes the data into folders. hashes all extracted data. hashes PowerShell and various system properties. and sends the data off to the security team. The data can be pushed to a share. sent over email. or retained locally.
        // Reference: https://github.com/gfoss/PSRecon
        $string1 = /\\PSRecon\\/ nocase ascii wide
        // Description: PSRecon gathers data from a remote Windows host using PowerShell (v2 or later). organizes the data into folders. hashes all extracted data. hashes PowerShell and various system properties. and sends the data off to the security team. The data can be pushed to a share. sent over email. or retained locally.
        // Reference: https://github.com/gfoss/PSRecon
        $string2 = /Invoke\-Recon\s/ nocase ascii wide
        // Description: PSRecon gathers data from a remote Windows host using PowerShell (v2 or later). organizes the data into folders. hashes all extracted data. hashes PowerShell and various system properties. and sends the data off to the security team. The data can be pushed to a share. sent over email. or retained locally.
        // Reference: https://github.com/gfoss/PSRecon
        $string3 = /PSRecon\.ps1/ nocase ascii wide

    condition:
        any of them
}
