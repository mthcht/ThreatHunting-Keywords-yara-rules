rule Shellcode_Hide
{
    meta:
        description = "Detection patterns for the tool 'Shellcode-Hide' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shellcode-Hide"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string1 = /\/IPfuscation\.cpp/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string2 = /\/IPfuscation\.exe/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string3 = /\/Shellcode\-Hide\.git/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string4 = /\/SimpleLoader\.cpp/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string5 = /\/SimpleLoader\.exe/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string6 = /\\CustomEncoding\.cpp/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string7 = /\\IPfuscation\.cpp/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string8 = /\\IPfuscation\.exe/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string9 = /\\SimpleLoader\.cpp/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string10 = /\\SimpleLoader\.exe/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string11 = /11385CC1\-54B7\-4968\-9052\-DF8BB1961F1E/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string12 = /1617117C\-0E94\-4E6A\-922C\-836D616EC1F5/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string13 = /497CA37F\-506C\-46CD\-9B8D\-F9BB0DA34B95/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string14 = /70527328\-DCEC\-4BA7\-9958\-B5BC3E48CE99/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string15 = /847D29FF\-8BBC\-4068\-8BE1\-D84B1089B3C0/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string16 = /9AA32BBF\-90F3\-4CE6\-B210\-CBCDB85052B0/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string17 = /B651A53C\-FAE6\-482E\-A590\-CA3B48B7F384/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string18 = /E991E6A7\-31EA\-42E3\-A471\-90F0090E3AFD/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string19 = /FilelessShellcode\.cpp/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string20 = /FilelessShellcode\.exe/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string21 = /FilelessShellcode\.sln/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string22 = /FilelessShellcode\.vcxproj/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string23 = /IPfuscation\.sln/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string24 = /IPfuscation\.vcxproj/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string25 = /MACshellcode\.cpp/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string26 = /MACshellcode\.exe/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string27 = /MACshellcode\.sln/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string28 = /MACshellcode\.vcxproj/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string29 = /Shellcode\-Hide\-main/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string30 = /TheD1rkMtr\/Shellcode\-Hide/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string31 = /WinhttpShellcode\.cpp/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string32 = /WinhttpShellcode\.exe/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string33 = /WinhttpShellcode\.sln/ nocase ascii wide
        // Description: simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // Reference: https://github.com/TheD1rkMtr/Shellcode-Hide
        $string34 = /WinhttpShellcode\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
