rule InflativeLoading
{
    meta:
        description = "Detection patterns for the tool 'InflativeLoading' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InflativeLoading"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string1 = /\sInflativeLoading\.py/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string2 = /\spsexec_merged\.bin/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string3 = /\sReadPEInMemory\.exe/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string4 = /\/InflativeLoading\.git/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string5 = /\/InflativeLoading\.py/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string6 = /\/InflativeLoading\-main\.zip/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string7 = /\/mimikatz\.bin/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string8 = /\[\!\]\sPRESS\sTO\sEXECUTE\sSHELLCODED\sEXE/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string9 = /\[\!\]\sShellcoded\sPE\\\'s\ssize\:\s/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string10 = /\[\#\]\sShellcode\slocated\sat\saddress\s/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string11 = /\\DumpPEFromMemory\.sln/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string12 = /\\DumpPEFromMemory\.vcxproj/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string13 = /\\InflativeLoading\.py/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string14 = /\\InflativeLoading\\bin\\.{0,1000}\.bin/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string15 = /\\InflativeLoading\\bin\\.{0,1000}\.exe/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string16 = /\\InflativeLoading\-main\.zip/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string17 = /\\mimikatz\.bin/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string18 = /\\ReadPEInMemory\.exe/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string19 = /DumpPEFromMemory\.cpp/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string20 = /DumpPEFromMemory\.exe/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string21 = /DumpPEFromMemoryMemory\.exe/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string22 = /Dynamically\sconvert\sa\snative\sPE\sto\sPIC\sshellcode/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string23 = /EEC48565\-5B42\-491A\-8BBB\-16AC0C40C367/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string24 = /Generated\sshellcode\ssuccessfully\ssaved\sin\sfile\s/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string25 = /InflativeLoading\.py\s/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string26 = /InflativeLoading\-DumpPEFromMemory/ nocase ascii wide
        // Description: Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // Reference: https://github.com/senzee1984/InflativeLoading
        $string27 = /senzee1984\/InflativeLoading/ nocase ascii wide

    condition:
        any of them
}
