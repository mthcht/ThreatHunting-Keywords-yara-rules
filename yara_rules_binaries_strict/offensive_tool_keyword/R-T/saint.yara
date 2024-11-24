rule saint
{
    meta:
        description = "Detection patterns for the tool 'saint' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "saint"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string1 = /\%appdata\%\\\(s\)AINT/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string2 = /\/sAINT\.git/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string3 = /\/sAINT\-master\.zip/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string4 = /\:\:\sRemove\s\(s\)AINT\sfolder/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string5 = /\\\(s\)AINT\\Cam/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string6 = /\\\(s\)AINT\\Logs/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string7 = /\\\(s\)AINT\\saint\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string8 = /\\\(s\)AINT\\Screenshot/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string9 = /\\\\saint\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string10 = /\\AppData\\Local\\Temp\\factura\.exe/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string11 = /\\sAINT\-master\.zip/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string12 = /\]\sEnable\sPersistence\s\(Y\/n\)\:\s/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string13 = /\]\sYou\swould\slike\sto\sgenerate\s\.EXE\susing\slauch4j\?\s\(y\/n\)\:/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string14 = /AppData\\Roaming\\\(s\)AINT/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string15 = /import\sorg\.jnativehook\.keyboard\.NativeKeyListener/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string16 = /import\ssaint\.email\.SendEmail/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string17 = /import\ssaint\.screenshot\.Screenshot/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string18 = /import\ssaint\.webcam\.Cam/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string19 = /java\s\-jar\ssAINT\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string20 = /java\s\-jar\ssAINT\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string21 = /Keylogger\.java/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string22 = /launch4j\slaunch4j\/sAINT\.xml/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string23 = /package\ssaint\.keylogger/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string24 = /package\ssaint\.webcam/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string25 = "public class Keylogger" nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string26 = /REG\sADD\sHKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\s\/V.{0,100}saint\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string27 = /reg\sdelete\sHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\s\/v\sSecurity\s\/f/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string28 = /sAINT.{0,100}launch4j\.tar\.xz/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string29 = /sAINT\\lib\\activation\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string30 = /saint\-1\.0\-jar\-with\-dependencies\.exe/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string31 = /saint\-1\.0\-jar\-with\-dependencies\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string32 = "tiagorlampert/sAINT" nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string33 = /ui\\sAINT\.java/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string34 = /webcam\-capture\-0\.3\.10\.jar/ nocase ascii wide
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
