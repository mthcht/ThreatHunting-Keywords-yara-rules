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
        $string1 = /G0ldenGunSec\/SharpSecDump/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string2 = /\/SharpSecDump\.git/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string3 = /SharpSecDump\-master/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string4 = /SharpSecDump\.sln/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string5 = /E2FDD6CC\-9886\-456C\-9021\-EE2C47CF67B7/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string6 = /SharpSecDump\.exe/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string7 = /SharpSecDump\.csproj/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string8 = /secretsdump\.py/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string9 = /SharpSecDump\sInfo/ nocase ascii wide

    condition:
        any of them
}
