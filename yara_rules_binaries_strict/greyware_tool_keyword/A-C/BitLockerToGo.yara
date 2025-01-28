rule BitLockerToGo
{
    meta:
        description = "Detection patterns for the tool 'BitLockerToGo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BitLockerToGo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/
        $string1 = /\/BitLockerToGo\.exe/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/
        $string2 = /\\Temp\\BitLockerToGo/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string3 = /BitLockerToGo.{0,100}\.kdbx/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string4 = /BitLockerToGo.{0,100}\\Network\\Cookies/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string5 = /BitLockerToGo.{0,100}360Browser/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string6 = /BitLockerToGo.{0,100}Anydesk/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string7 = /BitLockerToGo.{0,100}Binance/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string8 = /BitLockerToGo.{0,100}Bitcoin/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string9 = /BitLockerToGo.{0,100}BraveSoftware/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string10 = /BitLockerToGo.{0,100}CocCoc/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string11 = /BitLockerToGo.{0,100}Coinomi/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string12 = /BitLockerToGo.{0,100}ElectronCash/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string13 = /BitLockerToGo.{0,100}Electrum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string14 = /BitLockerToGo.{0,100}Electrum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string15 = /BitLockerToGo.{0,100}Electrum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string16 = /BitLockerToGo.{0,100}Electrum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string17 = /BitLockerToGo.{0,100}Epic\sPrivacy\sBrowser/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string18 = /BitLockerToGo.{0,100}Ethereum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string19 = /BitLockerToGo.{0,100}Exodus/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/
        $string20 = /BitLockerToGo.{0,100}Filezilla/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string21 = /BitLockerToGo.{0,100}Ledger/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string22 = /BitLockerToGo.{0,100}MailBird/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string23 = /BitLockerToGo.{0,100}metamask/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/
        $string24 = /BitLockerToGo.{0,100}telegram/ nocase ascii wide
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
