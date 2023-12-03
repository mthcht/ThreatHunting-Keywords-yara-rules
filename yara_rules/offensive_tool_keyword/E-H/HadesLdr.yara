rule HadesLdr
{
    meta:
        description = "Detection patterns for the tool 'HadesLdr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HadesLdr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string1 = /.{0,1000}\s\-h\s.{0,1000}\-p\s.{0,1000}\s\-c\scypher\.bin\s\-k\skey\.bin.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string2 = /.{0,1000}\/HadesLdr\.git.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string3 = /.{0,1000}\/scripts\/xor\.py.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string4 = /.{0,1000}CognisysGroup\/HadesLdr.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string5 = /.{0,1000}HadesLdr\-main.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string6 = /.{0,1000}IDSyscall\.exe.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string7 = /.{0,1000}IDSyscall\.sln.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string8 = /.{0,1000}IDSyscall\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string9 = /.{0,1000}IDSyscall\/IDSyscall.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string10 = /.{0,1000}IDSyscall\\IDSyscall.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string11 = /.{0,1000}python3\sGetHash\.py\sNtCreateFile.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string12 = /.{0,1000}rc4\.py\s.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string13 = /.{0,1000}syscallStuff\.asm.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string14 = /.{0,1000}xor\.py\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
