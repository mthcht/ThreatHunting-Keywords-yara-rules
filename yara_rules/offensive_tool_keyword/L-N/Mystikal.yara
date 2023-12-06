rule Mystikal
{
    meta:
        description = "Detection patterns for the tool 'Mystikal' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mystikal"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string1 = /\smystikal\.py/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string2 = /\/MacroWord_Payload\/macro\.txt/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string3 = /\/Mystikal\.git/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string4 = /\/mystikal\.py/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string5 = /\/PDF_Payload\/script\.txt/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string6 = /\\mystikal\.py/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string7 = /D00MFist\/Mystikal/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string8 = /Mystikal\-main/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string9 = /PDF_Payload.{0,1000}Doomfist\.pdf/ nocase ascii wide

    condition:
        any of them
}
