rule sharphound
{
    meta:
        description = "Detection patterns for the tool 'sharphound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sharphound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string1 = /\s\-c\sall\s\-d\s.{0,1000}\s\-\-domaincontroller\s/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string2 = /\s\-\-collectallproperties/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string3 = /\s\-\-CollectionMethod\sAll\s.{0,1000}ldap/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string4 = /\s\-\-CollectionMethod\sAll\s.{0,1000}\-\-ZipFileName\s.{0,1000}\.zip/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string5 = /\s\-\-collectionmethods\sACL/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string6 = /\s\-\-collectionmethods\sComputerOnly/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string7 = /\s\-\-collectionmethods\sContainer/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string8 = /\s\-\-collectionmethods\sDCOM/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string9 = /\s\-\-collectionmethods\sDCOnly/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string10 = /\s\-\-collectionmethods\sGPOLocalGroup/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string11 = /\s\-\-collectionmethods\sGroup/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string12 = /\s\-\-collectionmethods\sLocalGroup/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string13 = /\s\-\-collectionmethods\sLoggedOn/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string14 = /\s\-\-collectionmethods\sObjectProps/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string15 = /\s\-\-collectionmethods\sPSRemote/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string16 = /\s\-\-collectionmethods\sRDP/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string17 = /\s\-\-collectionmethods\sSession/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string18 = /\s\-\-collectionmethods\sTrusts/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string19 = /\s\-\-excludedcs/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string20 = /\s\-\-ldapusername\s\s.{0,1000}\s\-\-ldappassword\s/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string21 = /\-\s\-\-skippasswordcheck/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string22 = /\s\-\-skipregistryloggedon/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string23 = /\\SharpHoundCommon\\/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string24 = /BloodHoundAD/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string25 = /DisableKerberosSigning/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string26 = /GetDomainsForEnumeration/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string27 = /Invoke\-BloodHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string28 = /InvokeSharpHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string29 = /Out\-CompressedDLL\.ps1/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string30 = /Release\sof\sBloodHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string31 = /running\sSharpHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string32 = /SharpHound\-.{0,1000}\.zip/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string33 = /sharphound.{0,1000}\-\-stealth/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string34 = /sharphound\./ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string35 = /SharpHound\.exe/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string36 = /SharpHound\.ps1/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string37 = /SharpHound2/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string38 = /SharpHound3/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string39 = /SharpHoundCommon\./ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string40 = /SharpHoundCommonLib/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string41 = /SkipPasswordAgeCheck/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string42 = /SkipPortScan/ nocase ascii wide

    condition:
        any of them
}
