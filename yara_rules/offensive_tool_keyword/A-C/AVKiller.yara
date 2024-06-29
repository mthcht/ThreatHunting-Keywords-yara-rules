rule AVKiller
{
    meta:
        description = "Detection patterns for the tool 'AVKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AVKiller"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string1 = /\/AVKiller\.git/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string2 = /1y0n\/AVKiller/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string3 = /6eac306cec3650ed8740d82024380ccaaea2ac4b8f6b55119a9e5fb82485f67f/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string4 = /ba99e7ff67fb59ab551943030c912a2dfa0c9f1e1bba2c3e53a71aa5348386ec/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string5 = /dd35d7c7b99d5a0a182ff16546ebee8af08ee92510157d6f02355bae256d6191/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string6 = /https\:\/\/mp\.weixin\.qq\.com\/s\/GDPAC_9\-Pxfcj_z0_C_ixw/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string7 = /TerminateProcessFromId\(ID\(\"360rp\.exe\"\)/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string8 = /TerminateProcessFromId\(ID\(\"360rps\.exe\"\)/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string9 = /TerminateProcessFromId\(ID\(\"360sd\.exe\"\)/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string10 = /TerminateProcessFromId\(ID\(\"360tray\.exe\"\)/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string11 = /TerminateProcessFromId\(ID\(\"ZhuDongFangYu\.exe\"\)/ nocase ascii wide

    condition:
        any of them
}
