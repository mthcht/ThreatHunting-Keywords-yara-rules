rule SharpChromium
{
    meta:
        description = "Detection patterns for the tool 'SharpChromium' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpChromium"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string1 = /.{0,1000}\/SharpChromium\.git.{0,1000}/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string2 = /.{0,1000}djhohnstein\/SharpChromium.{0,1000}/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string3 = /.{0,1000}SharpChromium\.csproj.{0,1000}/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string4 = /.{0,1000}SharpChromium\.exe.{0,1000}/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string5 = /.{0,1000}SharpChromium\.sln.{0,1000}/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string6 = /.{0,1000}SharpChromium\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
