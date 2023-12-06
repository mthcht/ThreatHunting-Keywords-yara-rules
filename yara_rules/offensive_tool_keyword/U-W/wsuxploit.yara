rule wsuxploit
{
    meta:
        description = "Detection patterns for the tool 'wsuxploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wsuxploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a MiTM weaponized exploit script to inject 'fake' updates into non-SSL WSUS traffic. It is based on the WSUSpect Proxy application that was introduced to public on the Black Hat USA 2015 presentation. 'WSUSpect  Compromising the Windows Enterprise via Windows Update
        // Reference: https://github.com/pimps/wsuxploit
        $string1 = /wsuxploit/ nocase ascii wide

    condition:
        any of them
}
