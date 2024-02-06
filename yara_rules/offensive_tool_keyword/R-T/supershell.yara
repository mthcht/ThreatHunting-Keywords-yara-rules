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
        $string1 = /\s\-a\s\-t\stitleFixed\=\'Supershell\s\-\sInject\'\s\-t\sdisableLeaveAlert\=true\s\-t\sdisableReconnect\=true\sssh\s\-J\srssh\:/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string2 = /\s\-a\s\-t\stitleFixed\=\'Supershell\s\-\sShell\'\s\-t\sdisableLeaveAlert\=true\sssh\s\-J\srssh\:/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string3 = /\sSupershell\.tar\.gz/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string4 = /\/flask\:5000\/supershell\// nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string5 = /\/Supershell\.tar\.gz/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string6 = /\/supershell\/login\/auth/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string7 = /\/Supershell\/releases/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string8 = /\\Supershell\.tar\.gz/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string9 = /\\Supershell\\rssh\\pkg\\/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string10 = /\\Supershell\\rssh\\pkg\\/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string11 = /b7671f125bb2ed21d0476a00cfaa9ed6/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string12 = /http\:\/\/shell\:7681\/token/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string13 = /password\s\=\s\'tdragon6\'/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string14 = /supershell.{0,1000}winpty\.dll/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string15 = /supershell.{0,1000}winpty\-agent\.exe/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string16 = /tdragon6\/Supershell/ nocase ascii wide

    condition:
        any of them
}
