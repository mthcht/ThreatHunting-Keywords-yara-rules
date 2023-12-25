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
        $string1 = /\/SharpChromium\.git/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string2 = /\\SharpChromium\\/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string3 = /djhohnstein\/SharpChromium/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string4 = /F1653F20\-D47D\-4F29\-8C55\-3C835542AF5F/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string5 = /SharpChromium\.csproj/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string6 = /SharpChromium\.exe/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string7 = /SharpChromium\.sln/ nocase ascii wide
        // Description: .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // Reference: https://github.com/djhohnstein/SharpChromium
        $string8 = /SharpChromium\-master/ nocase ascii wide

    condition:
        any of them
}
