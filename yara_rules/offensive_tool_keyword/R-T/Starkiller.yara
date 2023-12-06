rule Starkiller
{
    meta:
        description = "Detection patterns for the tool 'Starkiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Starkiller"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Starkiller is a Frontend for Powershell Empire. It is an Electron application written in VueJS. If you'd like to contribute please follow the Contribution guide. If you'd like to request a feature or report a bug. please follow the Issue template.
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string1 = /Starkiller/ nocase ascii wide

    condition:
        any of them
}
