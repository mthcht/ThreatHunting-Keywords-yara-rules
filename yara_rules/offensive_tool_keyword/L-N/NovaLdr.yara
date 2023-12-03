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
        $string1 = /.{0,1000}\s\-f\sraw\s\-e\snone\s\-o\sNova_MSG\.bin.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string2 = /.{0,1000}\s\-p\swindows\/x64\/messagebox\sTITLE\=NovaLdr\s.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string3 = /.{0,1000}\/NovaLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string4 = /.{0,1000}\/NovaLdr\.git.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string5 = /.{0,1000}\/NoveLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string6 = /.{0,1000}\[\-\]\sShellcode\sis\slarger\sthan\sRX\ssection.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string7 = /.{0,1000}\[\+\]\sEncrypting\sThe\sStack\.\.\.\.\s.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string8 = /.{0,1000}\[\+\]\sRX\sInjection\saddress:\s.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string9 = /.{0,1000}\[\+\]\sThread\shijacking\ssuccessful.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string10 = /.{0,1000}\[\+\]\sThread\shijacking\ssuccessful.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string11 = /.{0,1000}\[\+\]\sUnhooking\sthe\sNTDLL\sfor\sProcess\swith\sPID\s.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string12 = /.{0,1000}\[\+\]\sUnhooking\sthe\sNTDLL\sfrom\sPID\s.{0,1000}\scompleted\ssuccessfully\..{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string13 = /.{0,1000}\\NovaLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string14 = /.{0,1000}\\NoveLdr\.exe/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string15 = /.{0,1000}BlackSnufkin\/NovaLdr.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string16 = /.{0,1000}C:\\\\Users\\\\L\.Ackerman\=.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string17 = /.{0,1000}encrypted_sleep\(ms:.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string18 = /.{0,1000}erase_dos_magic_bytes\(.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string19 = /.{0,1000}Failed\sto\sallocate\smemory\sfor\sshellcode:.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string20 = /.{0,1000}Failed\sto\schange\sshellcode\smemory\sprotection.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string21 = /.{0,1000}Failed\sto\sfind\srx\ssection\soffset.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string22 = /.{0,1000}Failed\sto\shijack\sthread:.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string23 = /.{0,1000}Failed\sto\soverwrite\sthe\s\.text\ssection\sof\sntdll\.dll.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string24 = /.{0,1000}Failed\sto\swrite\sshellcode\sto\starget\sprocess.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string25 = /.{0,1000}In\smemory\sof\sall\sthose\smurdered\sin\sthe\sNova\sparty\smassacre\s7\.10\.2023.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string26 = /.{0,1000}It2H\@Qp3Xe.{0,1000}sxdc\#KA8\)dbMtI5Q7\&FK.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string27 = /.{0,1000}janoglezcampos\/rust_syscalls.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string28 = /.{0,1000}jmp_hijack_thread\(.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string29 = /.{0,1000}NovaLdr\-main.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string30 = /.{0,1000}Threadless\sinjection\sfailed.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string31 = /.{0,1000}unhook_ntdll\(remote_process.{0,1000}/ nocase ascii wide
        // Description: NovaLdr is a Threadless Module Stomping written in Rust designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities
        // Reference: https://github.com/BlackSnufkin/NovaLdr
        $string32 = /.{0,1000}xor_encrypt\(.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
