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
        $string1 = /.{0,1000}\/BlockOpenHandle\.git.{0,1000}/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string2 = /.{0,1000}55F0368B\-63DA\-40E7\-A8A5\-289F70DF9C7F.{0,1000}/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string3 = /.{0,1000}BlockOpenHandle\.cpp.{0,1000}/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string4 = /.{0,1000}BlockOpenHandle\.exe.{0,1000}/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string5 = /.{0,1000}BlockOpenHandle\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // Reference: https://github.com/TheD1rkMtr/BlockOpenHandle
        $string6 = /.{0,1000}BlockOpenHandle\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
