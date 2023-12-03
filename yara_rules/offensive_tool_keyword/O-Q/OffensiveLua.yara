rule OffensiveLua
{
    meta:
        description = "Detection patterns for the tool 'OffensiveLua' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveLua"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string1 = /.{0,1000}\sc:\\\\Temp\\\\lua\.log.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string2 = /.{0,1000}\/bin2hex\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string3 = /.{0,1000}\/bindshell\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string4 = /.{0,1000}\/downloadexec\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string5 = /.{0,1000}\/OffensiveLua\.git.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string6 = /.{0,1000}\/regread\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string7 = /.{0,1000}\/regwrite\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string8 = /.{0,1000}\/regwritedel\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string9 = /.{0,1000}\/runcmd\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string10 = /.{0,1000}\/runcmd2\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string11 = /.{0,1000}\/runswhide\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string12 = /.{0,1000}\\\\Users\\\\Fantastic\\\\Desktop\\\\DEMO\\\\plugins\\\\scripts\\\\.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string13 = /.{0,1000}\\bin2hex\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string14 = /.{0,1000}\\bindshell\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string15 = /.{0,1000}\\downloadexec\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string16 = /.{0,1000}\\luajit\.exe.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string17 = /.{0,1000}\\regread\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string18 = /.{0,1000}\\regwrite\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string19 = /.{0,1000}\\regwritedel\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string20 = /.{0,1000}\\runcmd\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string21 = /.{0,1000}\\runcmd2\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string22 = /.{0,1000}\\runswhide\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string23 = /.{0,1000}\\x4d\\x5a\\x90\\x00\\x03\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\xff\\xff\\x00\\x00\\xb8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xf8\\x00\\x00\\x00\\x0e\\x1f\\xba\\x0e\\x00\\xb4\\x09\\xcd\\x21\\xb8\\x01\\x4c\\xcd\\x21\\x54\\x68\\x69\\x73\\x20\\x70\\x72.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string24 = /.{0,1000}C:\\\\temp\\\\test\.txt.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string25 = /.{0,1000}ComputerDefaultsUACBypass\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string26 = /.{0,1000}copy\sTsutsuji_x64\.dll\s\%appdata\%.{0,1000}Local\\Microsoft\\WindowsApps\\BluetoothDiagnosticUtil\.dll.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string27 = /.{0,1000}downloadexec_UACbypass\.lua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string28 = /.{0,1000}hackerhouse\-opensource\/OffensiveLua.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string29 = /.{0,1000}http:\/\/127\.0\.0\.1\/Renge_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string30 = /.{0,1000}OffensiveLua\-main.{0,1000}/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string31 = /.{0,1000}uac_bypass_bluetooth_win10\.lua.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
