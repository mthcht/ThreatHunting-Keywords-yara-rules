rule zeroday_powershell
{
    meta:
        description = "Detection patterns for the tool 'zeroday-powershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zeroday-powershell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This will exploit the Windows operating system allowing you to modify the file Some.dll.
        // Reference: https://github.com/OneLogicalMyth/zeroday-powershell
        $string1 = /zeroday\-powershell/ nocase ascii wide

    condition:
        any of them
}
