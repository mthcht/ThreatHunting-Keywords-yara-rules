rule modDetective
{
    meta:
        description = "Detection patterns for the tool 'modDetective' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "modDetective"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: modDetective is a small Python tool that chronologizes files based on modification time in order to investigate recent system activity. This can be used in red team engagements and CTFs in order to pinpoint where escalation and attack vectors may exist. This is especially true in CTFs. in which files associated with the challenges often have a much newer modification date than standard files that exist from install.
        // Reference: https://github.com/itsKindred/modDetective
        $string1 = /modDetective/ nocase ascii wide

    condition:
        any of them
}
