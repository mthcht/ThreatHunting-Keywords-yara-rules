rule SharpCookieMonster
{
    meta:
        description = "Detection patterns for the tool 'SharpCookieMonster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpCookieMonster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string1 = /execute\-assembly.{0,1000}sharpcookiemonster/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string2 = /m0rv4i\/SharpCookieMonster/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string3 = /SharpCookieMonster.{0,1000}WebSocket4Net\.dll/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string4 = /SharpCookieMonster\.csproj/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string5 = /SharpCookieMonster\.exe/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string6 = /SharpCookieMonster\.sln/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string7 = /SharpCookieMonsterOriginal\.exe/ nocase ascii wide

    condition:
        any of them
}
