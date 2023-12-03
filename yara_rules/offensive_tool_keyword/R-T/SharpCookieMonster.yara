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
        $string1 = /.{0,1000}execute\-assembly.{0,1000}sharpcookiemonster.{0,1000}/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string2 = /.{0,1000}m0rv4i\/SharpCookieMonster.{0,1000}/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string3 = /.{0,1000}SharpCookieMonster.{0,1000}WebSocket4Net\.dll.{0,1000}/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string4 = /.{0,1000}SharpCookieMonster\.csproj.{0,1000}/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string5 = /.{0,1000}SharpCookieMonster\.exe.{0,1000}/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string6 = /.{0,1000}SharpCookieMonster\.sln.{0,1000}/ nocase ascii wide
        // Description: This C# project will dump cookies for all sites. even those with httpOnly/secure/session
        // Reference: https://github.com/m0rv4i/SharpCookieMonster
        $string7 = /.{0,1000}SharpCookieMonsterOriginal\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
