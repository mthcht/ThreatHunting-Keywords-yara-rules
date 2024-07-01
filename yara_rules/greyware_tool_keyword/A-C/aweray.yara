rule aweray
{
    meta:
        description = "Detection patterns for the tool 'aweray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aweray"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string1 = /\.aweray\.net/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string2 = /\/Aweray_Remote_.{0,1000}\.exe/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string3 = /\/Aweray_Remote_.{0,1000}\.zip/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string4 = /\\Aweray\sRemote\.lnk/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string5 = /\\Aweray_Remote_.{0,1000}\.exe/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string6 = /\\Aweray_Remote_.{0,1000}\.zip/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string7 = /\\AweSun\.exe/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string8 = /\\Program\sFiles\\Aweray/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string9 = /\\Software\\AweSun\\SunLogin\\SunloginClient/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string10 = /\>AweRay\sLimited\</ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string11 = /\>AweRay\sPte\.\sLtd\.\</ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string12 = /\>AweSun\.exe\</ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string13 = /\>AweSun\</ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string14 = /asapi\.aweray\.net/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string15 = /as\-tk\.aweray\.com/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string16 = /as\-tk\.aweray\.com\/track/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string17 = /Aweray_Remote\.exe/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string18 = /awerayimg\.com/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string19 = /client\-api\.aweray\.com/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string20 = /https\:\/\/sun\.aweray\.com\/.{0,1000}\/download/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string21 = /install\.bat\sAweSun/ nocase ascii wide
        // Description: all-in-one secure remote access control and support solution
        // Reference: sun.aweray.com
        $string22 = /netsh\s\sadvfirewall\sfirewall\s.{0,1000}\srule\sname\=\"AweSun/ nocase ascii wide

    condition:
        any of them
}
