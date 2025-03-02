rule nimbo_c2
{
    meta:
        description = "Detection patterns for the tool 'nimbo-c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimbo-c2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string1 = /\/tmp\/metadata\/na\.elf/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string2 = /\[\+\]\skeystrokes\sdump\sfrom\sagent/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string3 = /agent\/dll\.nim/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string4 = /agent\/elf\.nim/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string5 = /agent\/exe\.nim/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string6 = /beacon\.elf/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string7 = /C\:\\ProgramData\\Prefetch\\na\.exe/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string8 = "C2 Framework for villains" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string9 = "download /etc/passwd"
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string10 = "dump_lsass" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string11 = /dump_sam\(/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string12 = "exit_nimbo" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string13 = "Itay Migdal" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string14 = "JAB4ACAAPQAgAEcAZQB0AC0AUAByAG8AYwBlAHMAcwAgAC0AUABJAEQAIAAkAHAAaQBkACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAG4AYQBtAGUAOwAgACIAJABwAGkAZAAgACQAeAAuAGUAeABlACIA" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string15 = "KABHAGUAdAAtAEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAIAAtAE4AYQBtAGUAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAbgBhAG0AZQApACAALQBjAG8AbgB0AGEAaQBuAHMAIABbAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAEkAZABlAG4AdABpAHQAeQBdADoAOgBHAGUAdABDAHUAcgByAGUAbgB0ACgAKQAuAG4AYQBtAGUA" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string16 = "keylogger is already off" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string17 = "keylogger stopped" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string18 = "lsass comsvcs" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string19 = "lsass direct" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string20 = "lsass dump from agent" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string21 = /lsass_.{0,100}\.dmp/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string22 = /memfd\simplant\s.{0,100}\.elf/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string23 = /memfd\stask\s.{0,100}\.elf/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string24 = "nimbo_main" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string25 = "nimbo_prompt_color" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string26 = "nimbo_root" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string27 = "Nimbo-C2 w1ll r0ck y0ur w0rld" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string28 = "Nimbo-C2" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string29 = /Nimbo\-C2\./ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string30 = "nimbo-dependencies" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string31 = /persist\srun\s.{0,100}hkcu/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string32 = /persist\srun\s.{0,100}hklm/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string33 = /persist\sspe\s.{0,100}\.exe/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string34 = /pstree\.ps1/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string35 = /reg\.exe\ssave\shklm\\sam/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string36 = /reg\.exe\ssave\shklm\\security/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string37 = /reg\.exe\ssave\shklm\\system/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string38 = "RwBlAHQALQBDAG8AbQBwAHUAdABlAHIASQBuAGYAbwAgAHwAIABzAGUAbABlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAVwBpAG4AZABvAHcAcwBQAHIAbwBkAHUAYwB0AE4AYQBtAGUA" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string39 = "RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAE4AZQB0AHcAbwByAGsAQQBkAGEAcAB0AGUAcgBDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAEkAUABBAGQAZAByAGUAcwBzACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAoACQAXwAgAC0AbABpAGsAZQAgACIAMQAwAC4AKgAuACoALgAqACIAKQAgAC0AbwByACAAKAAkAF8AIAAtAGwAaQBrAGUAIAAiADEAOQAyAC4AMQA2ADgALgAqAC4AKgAiACkAIAAtAG8AcgAgACgAJABfACAALQBsAGkAawBlACAAIgAxADcAMgAuADEANgA4AC4AKgAuACoAIgApAH0A" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string40 = /shellc\s.{0,100}\.bin\s/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string41 = /shellc\s.{0,100}\.shellc\s/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string42 = "uac fodhelper " nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string43 = "uac sdclt " nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string44 = "uac_bypass" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string45 = "wrap_execute_assembly" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string46 = "wrap_execute_encoded_powershell" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string47 = "wrap_get_clipboard" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string48 = "wrap_inject_shellc" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string49 = "wrap_load_memfd" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string50 = "wrap_unhook_ntdll" nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string51 = "WwBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBJAGQAZQBuAHQAaQB0AHkAXQA6ADoARwBlAHQAQwB1AHIAcgBlAG4AdAAoACkALgBuAGEAbQBlAAoA" nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
