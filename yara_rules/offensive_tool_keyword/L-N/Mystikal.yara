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
        $string1 = /.{0,1000}\smystikal\.py.{0,1000}/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string2 = /.{0,1000}\/MacroWord_Payload\/macro\.txt.{0,1000}/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string3 = /.{0,1000}\/Mystikal\.git.{0,1000}/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string4 = /.{0,1000}\/mystikal\.py.{0,1000}/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string5 = /.{0,1000}\/PDF_Payload\/script\.txt.{0,1000}/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string6 = /.{0,1000}\\mystikal\.py.{0,1000}/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string7 = /.{0,1000}D00MFist\/Mystikal.{0,1000}/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string8 = /.{0,1000}Mystikal\-main.{0,1000}/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string9 = /.{0,1000}PDF_Payload.{0,1000}Doomfist\.pdf.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
