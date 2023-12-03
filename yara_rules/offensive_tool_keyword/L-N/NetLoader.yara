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
        $string1 = /.{0,1000}\.exe\s\s\-\-b64\s\-\-path\s.{0,1000}\s\-\-args\s/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string2 = /.{0,1000}\/NetLoader\.git.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string3 = /.{0,1000}\\NetLoader\.exe.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string4 = /.{0,1000}csc\.exe\s\/t:exe\s\/out:RandomName\.exe\sProgram\.cs.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string5 = /.{0,1000}d2hvYW1p.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string6 = /.{0,1000}Flangvik\/NetLoader.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string7 = /.{0,1000}LOLBins\/NetLoader\.xml.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string8 = /.{0,1000}MSBuild\.exe\sNetLoader\.xml.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string9 = /.{0,1000}NetLoader\.exe\s\-\-path\s.{0,1000}\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string10 = /.{0,1000}NetLoader\-master.{0,1000}/ nocase ascii wide
        // Description: Loads any C# binary in memory - patching AMSI + ETW
        // Reference: https://github.com/Flangvik/NetLoader
        $string11 = /.{0,1000}U2VhdGJlbHQuZXhl.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
