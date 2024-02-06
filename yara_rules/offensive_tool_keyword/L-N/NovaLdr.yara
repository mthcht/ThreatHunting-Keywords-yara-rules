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
        $string2 = /\s\-p\swindows\/x64\/messagebox\sTITLE\=NovaLdr\s/ nocase ascii wide
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
        $string12 = /\[\+\]\sUnhooking\sthe\sNTDLL\sfrom\sPID\s.{0,1000}\scompleted\ssuccessfully\./ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string13 = /\\NovaLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string14 = /\\NoveLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string15 = /BlackSnufkin\/NovaLdr/ nocase ascii wide
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
        $string19 = /Failed\sto\sallocate\smemory\sfor\sshellcode\:/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string20 = /Failed\sto\schange\sshellcode\smemory\sprotection/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string21 = /Failed\sto\sfind\srx\ssection\soffset/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string22 = /Failed\sto\shijack\sthread\:/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string23 = /Failed\sto\soverwrite\sthe\s\.text\ssection\sof\sntdll\.dll/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string24 = /Failed\sto\swrite\sshellcode\sto\starget\sprocess/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string25 = /In\smemory\sof\sall\sthose\smurdered\sin\sthe\sNova\sparty\smassacre\s7\.10\.2023/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string26 = /It2H\@Qp3Xe.{0,1000}sxdc\#KA8\)dbMtI5Q7\&FK/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string27 = /janoglezcampos\/rust_syscalls/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string28 = /jmp_hijack_thread\(/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string29 = /NovaLdr\-main/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string30 = /Threadless\sinjection\sfailed/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string31 = /unhook_ntdll\(remote_process/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string32 = /xor_encrypt\(/ nocase ascii wide

    condition:
        any of them
}
