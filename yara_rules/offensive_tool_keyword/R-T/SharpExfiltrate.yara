rule SharpExfiltrate
{
    meta:
        description = "Detection patterns for the tool 'SharpExfiltrate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExfiltrate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string1 = /.{0,1000}\.exe\sAzureStorage\s\-\-connectionstring\s.{0,1000}\s\-\-filepath\s.{0,1000}\s\-\-extensions\s.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string2 = /.{0,1000}\.exe\sGoogleDrive\s\-\-appname\s.{0,1000}\s\-\-accesstoken\s.{0,1000}\s\-\-filepath\s.{0,1000}\s\-\-extensions\s.{0,1000}\s\-\-memoryonly.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string3 = /.{0,1000}\.exe\sOneDrive\s\-\-username\s.{0,1000}\s\-\-password\s.{0,1000}\s\-\-filepath\s.{0,1000}\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string4 = /.{0,1000}\/SharpExfiltrate\.git.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string5 = /.{0,1000}\/SharpExfiltrate\/.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string6 = /.{0,1000}\\SharpExfiltrate\\.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string7 = /.{0,1000}3bb553cd\-0a48\-402d\-9812\-8daff60ac628.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string8 = /.{0,1000}Flangvik\/SharpExfiltrate.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string9 = /.{0,1000}SharpExfiltrate\.csproj.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string10 = /.{0,1000}SharpExfiltrate\.exe.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string11 = /.{0,1000}SharpExfiltrate\.sln.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string12 = /.{0,1000}SharpExfiltrateLootCache.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string13 = /.{0,1000}SharpExfiltrate\-main.{0,1000}/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string14 = /.{0,1000}using\sSharpExfiltrate.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
