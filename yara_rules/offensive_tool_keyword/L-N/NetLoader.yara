rule NetLoader
{
    meta:
        description = "Detection patterns for the tool 'NetLoader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetLoader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string1 = /\.exe\s\s\-\-b64\s\-\-path\s.{0,1000}\s\-\-args\s/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string2 = /\/NetLoader\.git/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string3 = /\\NetLoader\.exe/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string4 = /csc\.exe\s\/t\:exe\s\/out\:RandomName\.exe\sProgram\.cs/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string5 = /d2hvYW1p/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string6 = /Flangvik\/NetLoader/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string7 = /LOLBins\/NetLoader\.xml/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string8 = /MSBuild\.exe\sNetLoader\.xml/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string9 = /NetLoader\.exe\s\-\-path\s.{0,1000}\.exe\s/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string10 = /NetLoader\-master/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string11 = /U2VhdGJlbHQuZXhl/ nocase ascii wide

    condition:
        any of them
}
