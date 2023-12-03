rule supershell
{
    meta:
        description = "Detection patterns for the tool 'supershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "supershell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string1 = /.{0,1000}\s\-a\s\-t\stitleFixed\=\'Supershell\s\-\sInject\'\s\-t\sdisableLeaveAlert\=true\s\-t\sdisableReconnect\=true\sssh\s\-J\srssh:.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string2 = /.{0,1000}\s\-a\s\-t\stitleFixed\=\'Supershell\s\-\sShell\'\s\-t\sdisableLeaveAlert\=true\sssh\s\-J\srssh:.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string3 = /.{0,1000}\sSupershell\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string4 = /.{0,1000}\/flask:5000\/supershell\/.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string5 = /.{0,1000}\/Supershell\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string6 = /.{0,1000}\/supershell\/login\/auth.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string7 = /.{0,1000}\/Supershell\/releases.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string8 = /.{0,1000}\\Supershell\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string9 = /.{0,1000}\\Supershell\\rssh\\pkg\\.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string10 = /.{0,1000}\\Supershell\\rssh\\pkg\\.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string11 = /.{0,1000}b7671f125bb2ed21d0476a00cfaa9ed6.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string12 = /.{0,1000}http:\/\/shell:7681\/token.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string13 = /.{0,1000}password\s\=\s\'tdragon6\'.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string14 = /.{0,1000}supershell.{0,1000}winpty\.dll.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string15 = /.{0,1000}supershell.{0,1000}winpty\-agent\.exe.{0,1000}/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string16 = /.{0,1000}tdragon6\/Supershell.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
