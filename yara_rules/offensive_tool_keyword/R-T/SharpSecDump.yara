rule SharpSecDump
{
    meta:
        description = "Detection patterns for the tool 'SharpSecDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSecDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string1 = /\/SharpSecDump\.git/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string2 = /4bb5b8961566bdbdc3787a847a55730ce32d1822677bcd7c412cf2d7f54262fd/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string3 = /E2FDD6CC\-9886\-456C\-9021\-EE2C47CF67B7/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string4 = /fbee25dd2d6b1faf917f4f6a90113e3c520125f325915b7dd70f304dd2dab4b1/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string5 = /G0ldenGunSec\/SharpSecDump/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string6 = /secretsdump\.py/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string7 = /SharpSecDump\sInfo/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string8 = /SharpSecDump\.csproj/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string9 = /SharpSecDump\.exe/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string10 = /SharpSecDump\.sln/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string11 = /SharpSecDump\-master/ nocase ascii wide

    condition:
        any of them
}
