rule PickleC2
{
    meta:
        description = "Detection patterns for the tool 'PickleC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PickleC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string1 = /\/PickleC2\.git/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string2 = /\\Implants\\powershell\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string3 = /\\PickleC2\\Core\\.{0,100}\.py/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string4 = /\\PowerUp\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string5 = /data\/implant\/.{0,100}\/host\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string6 = /Find\-PathDLLHijack/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string7 = /Find\-ProcessDLLHijack/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string8 = /http\:\/\/.{0,100}\:.{0,100}\/down\/.{0,100}\/host\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string9 = /IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA\=/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string10 = /Implants\/powershell\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string11 = /Invoke\-EventVwrBypass/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string12 = /Invoke\-PrivescAudit\s/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string13 = /Invoke\-ServiceAbuse/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string14 = /module\spowerup/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string15 = /PickleC2\-main/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string16 = /UACBypassTest\.txt/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string17 = /Write\-HijackDll/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string18 = /xRET2pwn\/PickleC2/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
