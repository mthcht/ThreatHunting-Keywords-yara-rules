rule SharpSC
{
    meta:
        description = "Detection patterns for the tool 'SharpSC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string1 = /\.exe\saction\=create\s.{0,1000}\sservice\=.{0,1000}\sdisplayname\=.{0,1000}\sbinpath\=.{0,1000}/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string2 = /\/SharpSC\.exe/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string3 = /\/SharpSC\.git/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string4 = /\\SharpSC\.exe/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string5 = /\\SharpSC\-main/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string6 = /3b6a44069c343b15c9bafec9feb7d5597f936485c68f29316e96fe97aa15d06d/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string7 = /3D9D679D\-6052\-4C5E\-BD91\-2BC3DED09D0A/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string8 = /4c0fdf591ecec6aaeb3b6529f7b3800125910f16bc23496ba279a4bee0c2361c/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string9 = /9870daa238c3cab7fa949a1f8b80d3451c78eb07d18030ad061d8b91d612decc/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string10 = /djhohnstein\/SharpSC/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string11 = /namespace\sSharpSC/ nocase ascii wide

    condition:
        any of them
}
