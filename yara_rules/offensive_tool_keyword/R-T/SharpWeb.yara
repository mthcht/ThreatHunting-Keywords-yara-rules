rule SharpWeb
{
    meta:
        description = "Detection patterns for the tool 'SharpWeb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpWeb"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string1 = /\.exe\s\-b\schromium\s\-p\s.{0,1000}\\AppData\\Local\\Google\\Chrome\\/ nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string2 = /\/SharpWeb\.exe/ nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string3 = /\/SharpWeb\.git/ nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string4 = /\\SharpWeb\.exe/ nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string5 = /\\SharpWeb\.sln/ nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string6 = ">SharpWeb<" nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string7 = "1c309b473a4221fa7bbb5566935f888a7d8cf523ea33c6f7b568c7342f81419a" nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string8 = "1e2744c89803f6afc884b214ba4a8f47dfc1725a4180d767630205feeead064b" nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string9 = "91292bac-72b4-4aab-9e5f-2bc1843c8ea3" nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string10 = "99292BAC-72B4-4AAB-9E5F-2BC1843C8EA3" nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string11 = "AE844C23-294E-4690-8CF3-2E5F9769D8E0" nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string12 = /decrypt_chrome_v20_cookie\.py/ nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string13 = /SharpWeb\.exe\s\-/ nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string14 = "StarfireLab/SharpWeb" nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string15 = "sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=" nocase ascii wide
        // Description: SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // Reference: https://github.com/StarfireLab/SharpWeb
        $string16 = /vaultSchema\.Add\(new\sGuid\(\\"\\"4BF4C442\-9B8A\-41A0\-B380\-DD4A704DDB28\\"\\"/ nocase ascii wide

    condition:
        any of them
}
