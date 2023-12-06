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
        $string1 = /\s\-h\s.{0,1000}\-p\s.{0,1000}\s\-c\scypher\.bin\s\-k\skey\.bin/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string2 = /\/HadesLdr\.git/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string3 = /\/scripts\/xor\.py/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string4 = /CognisysGroup\/HadesLdr/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string5 = /HadesLdr\-main/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string6 = /IDSyscall\.exe/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string7 = /IDSyscall\.sln/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string8 = /IDSyscall\.vcxproj/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string9 = /IDSyscall\/IDSyscall/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string10 = /IDSyscall\\IDSyscall/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string11 = /python3\sGetHash\.py\sNtCreateFile/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string12 = /rc4\.py\s.{0,1000}\.bin/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string13 = /syscallStuff\.asm/ nocase ascii wide
        // Description: Shellcode Loader Implementing Indirect Dynamic Syscall - API Hashing - Fileless Shellcode retrieving using Winsock2
        // Reference: https://github.com/CognisysGroup/HadesLdr
        $string14 = /xor\.py\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}
