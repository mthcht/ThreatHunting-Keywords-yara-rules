rule DataBouncing
{
    meta:
        description = "Detection patterns for the tool 'DataBouncing' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DataBouncing"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string1 = /Unit\-259\/DataBouncing/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string2 = /\/DataBouncing\.git/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string3 = /DataBouncing\-main\.zip/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string4 = /\/nightCrawler\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string5 = /\\nightCrawler\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string6 = /\snightCrawler\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string7 = /nightCrawler\.ps1\s/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string8 = /\swget\s\"https:\/\/.{0,1000}\/interactshbuild/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string9 = /irm\sunit259\.fyi\/dbgui\s\|\siex/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string10 = /exfil\s\-regex.{0,1000}\s\-domain.{0,1000}\-url\s.{0,1000}\s\-filepath\s/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string11 = /\/deadPool\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string12 = /\\deadPool\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string13 = /\sdeadPool\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string14 = /Find\-Secret\s\-FilePath\s\.\/logs\.txt\s\-Regex\s/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string15 = /bash\s\.\/bounce\.sh/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string16 = /https:\/\/unit259\.fyi\/db/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string17 = /\\exfilGui\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string18 = /\/exfilGui\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string19 = /\sexfilGui\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string20 = /clndh3qilvdv6403g1n0hs3rhd6xpfmjn\.oast\.online/ nocase ascii wide

    condition:
        any of them
}
