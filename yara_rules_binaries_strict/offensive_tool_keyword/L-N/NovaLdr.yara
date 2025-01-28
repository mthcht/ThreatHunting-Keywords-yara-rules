rule NovaLdr
{
    meta:
        description = "Detection patterns for the tool 'NovaLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NovaLdr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string1 = /\s\-f\sraw\s\-e\snone\s\-o\sNova_MSG\.bin/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string2 = " -p windows/x64/messagebox TITLE=NovaLdr " nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string3 = /\/NovaLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string4 = /\/NovaLdr\.git/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string5 = /\/NoveLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string6 = /\[\-\]\sShellcode\sis\slarger\sthan\sRX\ssection/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string7 = /\[\+\]\sEncrypting\sThe\sStack\.\.\.\.\s/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string8 = /\[\+\]\sRX\sInjection\saddress\:\s/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string9 = /\[\+\]\sThread\shijacking\ssuccessful/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string10 = /\[\+\]\sThread\shijacking\ssuccessful/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string11 = /\[\+\]\sUnhooking\sthe\sNTDLL\sfor\sProcess\swith\sPID\s/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string12 = /\[\+\]\sUnhooking\sthe\sNTDLL\sfrom\sPID\s.{0,100}\scompleted\ssuccessfully\./ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string13 = /\\NovaLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string14 = /\\NoveLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string15 = "BlackSnufkin/NovaLdr" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string16 = /C\:\\\\Users\\\\L\.Ackerman\=/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string17 = /encrypted_sleep\(ms\:/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string18 = /erase_dos_magic_bytes\(/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string19 = "Failed to allocate memory for shellcode:" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string20 = "Failed to change shellcode memory protection" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string21 = "Failed to find rx section offset" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string22 = "Failed to hijack thread:" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string23 = /Failed\sto\soverwrite\sthe\s\.text\ssection\sof\sntdll\.dll/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string24 = "Failed to write shellcode to target process" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string25 = /In\smemory\sof\sall\sthose\smurdered\sin\sthe\sNova\sparty\smassacre\s7\.10\.2023/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string26 = /It2H\@Qp3Xe.{0,100}sxdc\#KA8\)dbMtI5Q7\&FK/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string27 = "janoglezcampos/rust_syscalls" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string28 = /jmp_hijack_thread\(/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string29 = "NovaLdr-main" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string30 = "Threadless injection failed" nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string31 = /unhook_ntdll\(remote_process/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string32 = /xor_encrypt\(/ nocase ascii wide
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
