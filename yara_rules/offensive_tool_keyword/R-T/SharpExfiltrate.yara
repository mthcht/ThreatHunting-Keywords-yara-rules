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
        $string1 = /\.exe\sAzureStorage\s\-\-connectionstring\s.*\s\-\-filepath\s.*\s\-\-extensions\s/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string2 = /\.exe\sGoogleDrive\s\-\-appname\s.*\s\-\-accesstoken\s.*\s\-\-filepath\s.*\s\-\-extensions\s.*\s\-\-memoryonly/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string3 = /\.exe\sOneDrive\s\-\-username\s.*\s\-\-password\s.*\s\-\-filepath\s.*\\.*\.exe/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string4 = /\/SharpExfiltrate\.git/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string5 = /\/SharpExfiltrate\// nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string6 = /\\SharpExfiltrate\\/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string7 = /3bb553cd\-0a48\-402d\-9812\-8daff60ac628/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string8 = /Flangvik\/SharpExfiltrate/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string9 = /SharpExfiltrate\.csproj/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string10 = /SharpExfiltrate\.exe/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string11 = /SharpExfiltrate\.sln/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string12 = /SharpExfiltrateLootCache/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string13 = /SharpExfiltrate\-main/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string14 = /using\sSharpExfiltrate/ nocase ascii wide

    condition:
        any of them
}