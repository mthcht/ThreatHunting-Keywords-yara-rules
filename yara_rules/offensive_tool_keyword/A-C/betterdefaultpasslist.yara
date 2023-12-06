rule betterdefaultpasslist
{
    meta:
        description = "Detection patterns for the tool 'betterdefaultpasslist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "betterdefaultpasslist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: list includes default credentials from various manufacturers for their products like NAS. ERP. ICS etc.. that are used for standard products like mssql. vnc. oracle and so on useful for network bruteforcing
        // Reference: https://github.com/govolution/betterdefaultpasslist
        $string1 = /betterdefaultpasslist/ nocase ascii wide

    condition:
        any of them
}
