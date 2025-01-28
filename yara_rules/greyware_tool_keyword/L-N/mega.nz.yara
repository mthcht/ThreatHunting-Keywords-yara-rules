rule mega_nz
{
    meta:
        description = "Detection patterns for the tool 'mega.nz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mega.nz"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Direct file download links on Mega.nz - file sharing activity often abused by attackers for Collection
        // Reference: N/A
        $string1 = /https\:\/\/mega\.nz\/file\// nocase ascii wide
        // Description: Direct folder sharing links on Mega.nz for accessing multiple files - file sharing activity often abused by attackers for Collection
        // Reference: N/A
        $string2 = /https\:\/\/mega\.nz\/folder\// nocase ascii wide

    condition:
        any of them
}
