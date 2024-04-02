rule ADFSDump
{
    meta:
        description = "Detection patterns for the tool 'ADFSDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string1 = /\!\!\!\sAre\syou\ssure\syou\sare\srunning\sas\sthe\sAD\sFS\sservice\saccount\?/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string2 = /\#\#\sExtracting\sPrivate\sKey\sfrom\sActive\sDirectory\sStore/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string3 = /\/ADFSDump\.git/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string4 = /\\ADFSDump\./ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string5 = /\\ADFSDump\\/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string6 = /\\ADFSDump\-master/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string7 = /46d1f15077f064a99b06bb115ba498581828ff8b712b2c41f6eb602538077035/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string8 = /7aa369f9365c35abe1cfea6a209a8a6071d7af3377a357f94721860c02e4d332/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string9 = /9EE27D63\-6AC9\-4037\-860B\-44E91BAE7F0D/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string10 = /ADFSDump\.csproj/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string11 = /ADFSDump\.exe/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string12 = /ADFSDump\.sln/ nocase ascii wide
        // Description: A C# tool to dump all sorts of goodies from AD FS
        // Reference: https://github.com/mandiant/ADFSDump
        $string13 = /mandiant\/ADFSDump/ nocase ascii wide

    condition:
        any of them
}
