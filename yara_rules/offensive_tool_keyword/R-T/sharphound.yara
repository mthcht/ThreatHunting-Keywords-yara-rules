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
        $string1 = /.{0,1000}\s\-c\sall\s\-d\s.{0,1000}\s\-\-domaincontroller\s.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string2 = /.{0,1000}\s\-\-collectallproperties.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string3 = /.{0,1000}\s\-\-CollectionMethod\sAll\s.{0,1000}ldap.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string4 = /.{0,1000}\s\-\-CollectionMethod\sAll\s.{0,1000}\-\-ZipFileName\s.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string5 = /.{0,1000}\s\-\-collectionmethods\sACL.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string6 = /.{0,1000}\s\-\-collectionmethods\sComputerOnly.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string7 = /.{0,1000}\s\-\-collectionmethods\sContainer.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string8 = /.{0,1000}\s\-\-collectionmethods\sDCOM/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string9 = /.{0,1000}\s\-\-collectionmethods\sDCOnly.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string10 = /.{0,1000}\s\-\-collectionmethods\sGPOLocalGroup.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string11 = /.{0,1000}\s\-\-collectionmethods\sGroup.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string12 = /.{0,1000}\s\-\-collectionmethods\sLocalGroup.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string13 = /.{0,1000}\s\-\-collectionmethods\sLoggedOn.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string14 = /.{0,1000}\s\-\-collectionmethods\sObjectProps.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string15 = /.{0,1000}\s\-\-collectionmethods\sPSRemote.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string16 = /.{0,1000}\s\-\-collectionmethods\sRDP.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string17 = /.{0,1000}\s\-\-collectionmethods\sSession.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string18 = /.{0,1000}\s\-\-collectionmethods\sTrusts.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string19 = /.{0,1000}\s\-\-excludedcs.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string20 = /.{0,1000}\s\-\-ldapusername\s\s.{0,1000}\s\-\-ldappassword\s.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string21 = /.{0,1000}\-\s\-\-skippasswordcheck.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string22 = /.{0,1000}\s\-\-skipregistryloggedon.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string23 = /.{0,1000}\\SharpHoundCommon\\.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string24 = /.{0,1000}BloodHoundAD.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string25 = /.{0,1000}DisableKerberosSigning.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string26 = /.{0,1000}GetDomainsForEnumeration.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string27 = /.{0,1000}Invoke\-BloodHound.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string28 = /.{0,1000}InvokeSharpHound.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string29 = /.{0,1000}Out\-CompressedDLL\.ps1.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string30 = /.{0,1000}Release\sof\sBloodHound.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string31 = /.{0,1000}running\sSharpHound.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string32 = /.{0,1000}SharpHound\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string33 = /.{0,1000}sharphound.{0,1000}\-\-stealth.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string34 = /.{0,1000}sharphound\..{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string35 = /.{0,1000}SharpHound\.exe.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string36 = /.{0,1000}SharpHound\.ps1.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string37 = /.{0,1000}SharpHound2.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string38 = /.{0,1000}SharpHound3.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string39 = /.{0,1000}SharpHoundCommon\..{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string40 = /.{0,1000}SharpHoundCommonLib.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string41 = /.{0,1000}SkipPasswordAgeCheck.{0,1000}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string42 = /.{0,1000}SkipPortScan.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
