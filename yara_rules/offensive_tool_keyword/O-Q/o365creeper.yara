rule o365creeper
{
    meta:
        description = "Detection patterns for the tool 'o365creeper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365creeper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python script that performs email address validation against Office 365 without submitting login attempts
        // Reference: https://github.com/LMGsec/o365creeper
        $string1 = /.{0,1000}o365creeper\.git.{0,1000}/ nocase ascii wide
        // Description: Python script that performs email address validation against Office 365 without submitting login attempts
        // Reference: https://github.com/LMGsec/o365creeper
        $string2 = /.{0,1000}o365creeper\.py.{0,1000}/ nocase ascii wide
        // Description: Python script that performs email address validation against Office 365 without submitting login attempts
        // Reference: https://github.com/LMGsec/o365creeper
        $string3 = /.{0,1000}o365creeper\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
