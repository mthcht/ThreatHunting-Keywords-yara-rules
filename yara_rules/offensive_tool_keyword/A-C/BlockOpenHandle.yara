rule BlockOpenHandle
{
    meta:
        description = "Detection patterns for the tool 'BlockOpenHandle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockOpenHandle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string1 = /\/BlockOpenHandle\.git/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string2 = /55F0368B\-63DA\-40E7\-A8A5\-289F70DF9C7F/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string3 = /BlockOpenHandle\.cpp/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string4 = /BlockOpenHandle\.exe/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string5 = /BlockOpenHandle\.vcxproj/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string6 = /BlockOpenHandle\-main/ nocase ascii wide

    condition:
        any of them
}
