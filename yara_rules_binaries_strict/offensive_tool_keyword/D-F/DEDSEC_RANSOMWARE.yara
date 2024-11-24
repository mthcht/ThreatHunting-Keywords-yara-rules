rule DEDSEC_RANSOMWARE
{
    meta:
        description = "Detection patterns for the tool 'DEDSEC-RANSOMWARE' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DEDSEC-RANSOMWARE"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string1 = /\.\/dedsec_ransomware/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string2 = /\/DEDSEC\-RANSOMWARE\.git/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string3 = /\\Desktop\\.{0,100}\.dedsec/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string4 = /\\Documents\\.{0,100}\.dedsec/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string5 = "1da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd7871da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd787" nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string6 = "8a2f2dcdf0a2f4b3bf2c7ac94205e769dfcdb7c161df5a8d9df52935dbaeb936" nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string7 = "dedsec1da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd7871da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd787" nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string8 = /DEDSEC\-RANSOMWARE\.py/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string9 = /endswith\(\'\.dedsec\'\)/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string10 = "GludXhsb2NhbGhvc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nl82NDE2MTM0ODExNjQ4NTAxMzg2MDQzMzky" nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string11 = /https\:\/\/discord\.com\/api\/webhooks\/1172456340560560180\/KwaMHIPwjfbQIhVUB\-mOHNRiHoNnyAzzQcvgvjJHqGAfLSXahTDKwB1SVuq__NVlPbeQ/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string12 = /https\:\/\/media0\.giphy\.com\/media\/l0IynvAIYxm8ZGUrm\/giphy\.gif\?cid\=ecf05e47qvbyv5iod2z91r9bufnpkvsjn1xm18a63b0g8z9a\&ep\=v1_gifs_related\&rid\=giphy\.gif\&ct\=g/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string13 = /https\:\/\/pyobfuscate\.com\/pyd/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string14 = /Oops\!\sYour\sfiles\shave\sbeen\sencrypted\..{0,100}recover\sall\syour\sfiles\ssafely/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string15 = /t\.me\/dedsecransom/ nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string16 = "UklGRjT7DwBXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YRD7DwD" nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string17 = "xelroth/DEDSEC-RANSOMWARE" nocase ascii wide
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string18 = "YOUR FILES HAVE BEEN SUCCESSFULLY DECRYPTED" nocase ascii wide
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
