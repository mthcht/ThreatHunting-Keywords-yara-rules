rule unset
{
    meta:
        description = "Detection patterns for the tool 'unset' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unset"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: disable history logging
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/OMGLogger
        $string1 = /.{0,1000}unset\sHISTFILE\s\&\&\sHISTSIZE\=0\s\&\&\srm\s\-f\s\$HISTFILE\s\&\&\sunset\sHISTFILE.{0,1000}/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /.{0,1000}unset\sHISTFILE.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
