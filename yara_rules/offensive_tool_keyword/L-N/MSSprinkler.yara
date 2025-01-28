rule MSSprinkler
{
    meta:
        description = "Detection patterns for the tool 'MSSprinkler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSSprinkler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string1 = /\smssprinkler\.ps1/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string2 = /\s\-user\suserlist\.txt\s\-pass\spasswordlist\.txt\s/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string3 = /\/MSSprinkler\.git/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string4 = /\/mssprinkler\.ps1/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string5 = /\\mssprinkler\.ps1/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string6 = "c299346734b17df1a8dc47d97145c756938307fbd249837ff4dc697befd2961b" nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string7 = "Invoke-MSSprinkler" nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string8 = "TheresAFewConors/MSSprinkler" nocase ascii wide

    condition:
        any of them
}
