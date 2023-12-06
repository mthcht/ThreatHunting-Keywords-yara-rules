rule NetshRun
{
    meta:
        description = "Detection patterns for the tool 'NetshRun' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetshRun"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Netsh.exe relies on extensions taken from Registry which means it may be used as a persistence and you go one step further extending netsh with a DLL allowing you to do whatever you want
        // Reference: https://github.com/gtworek/PSBits/blob/master/NetShRun
        $string1 = /\/netshrun\.c/ nocase ascii wide
        // Description: Netsh.exe relies on extensions taken from Registry which means it may be used as a persistence and you go one step further extending netsh with a DLL allowing you to do whatever you want
        // Reference: https://github.com/gtworek/PSBits/blob/master/NetShRun
        $string2 = /netsh\.exe\sadd\shelper\s.{0,1000}\\temp\\.{0,1000}\.dll/ nocase ascii wide
        // Description: Netsh.exe relies on extensions taken from Registry which means it may be used as a persistence and you go one step further extending netsh with a DLL allowing you to do whatever you want
        // Reference: https://github.com/gtworek/PSBits/blob/master/NetShRun
        $string3 = /netshrun\.dll/ nocase ascii wide
        // Description: Netsh.exe relies on extensions taken from Registry which means it may be used as a persistence and you go one step further extending netsh with a DLL allowing you to do whatever you want
        // Reference: https://github.com/gtworek/PSBits/blob/master/NetShRun
        $string4 = /PSBits.{0,1000}NetShRun/ nocase ascii wide

    condition:
        any of them
}
