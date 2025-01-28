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
        $string3 = /BitLockerToGo.{0,1000}\.kdbx/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string4 = /BitLockerToGo.{0,1000}\\Network\\Cookies/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string5 = /BitLockerToGo.{0,1000}360Browser/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string6 = /BitLockerToGo.{0,1000}Anydesk/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string7 = /BitLockerToGo.{0,1000}Binance/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string8 = /BitLockerToGo.{0,1000}Bitcoin/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string9 = /BitLockerToGo.{0,1000}BraveSoftware/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string10 = /BitLockerToGo.{0,1000}CocCoc/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string11 = /BitLockerToGo.{0,1000}Coinomi/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string12 = /BitLockerToGo.{0,1000}ElectronCash/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string13 = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string14 = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string15 = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string16 = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string17 = /BitLockerToGo.{0,1000}Epic\sPrivacy\sBrowser/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string18 = /BitLockerToGo.{0,1000}Ethereum/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string19 = /BitLockerToGo.{0,1000}Exodus/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/
        $string20 = /BitLockerToGo.{0,1000}Filezilla/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string21 = /BitLockerToGo.{0,1000}Ledger/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string22 = /BitLockerToGo.{0,1000}MailBird/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/
        $string23 = /BitLockerToGo.{0,1000}metamask/ nocase ascii wide
        // Description: BitLocker To Go is legitimate Windows utility used for managing BitLocker encryption - abused by Malware like LummaSteale to manipulate registry keys -  search for cryptocurrency wallets and credentials and exfiltrate sensitive data
        // Reference: https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/
        $string24 = /BitLockerToGo.{0,1000}telegram/ nocase ascii wide

    condition:
        any of them
}
