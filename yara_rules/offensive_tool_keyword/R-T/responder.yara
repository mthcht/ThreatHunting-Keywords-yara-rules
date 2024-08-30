rule responder
{
    meta:
        description = "Detection patterns for the tool 'responder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "responder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string1 = /\sPoisoners\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string2 = /\/Analyzer\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string3 = /\/FindSQLSrv\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string4 = /\/NBTNS\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string5 = /\/poisoners\/.{0,1000}\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string6 = /\/Poisoners\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string7 = /\/Responder\.git/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string8 = /\/responder\/Responder\.conf\s/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string9 = /\/Responder\-master\.zip/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string10 = /\/Responder\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string11 = /\/Responder\-Windows\.git/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string12 = /\/tools\/DHCP\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string13 = /\\\\Windows\\\\Temp\\\\Results\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string14 = /\\BindShell\.exe/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string15 = /\\cachedump\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string16 = /\\FTP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string17 = /\\HTTP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string18 = /\\HTTP\-NTLMv1\-Client\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string19 = /\\HTTP\-NTLMv2\-Client\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string20 = /\\IMAP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string21 = /\\LDAP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string22 = /\\LDAP\-NTLMv1\-Client\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string23 = /\\lsadump\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string24 = /\\MSSQL\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string25 = /\\MSSQL\-NTLMv1\-Client\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string26 = /\\MSSQL\-NTLMv2\-Client\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string27 = /\\Poisoners\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string28 = /\\POP3\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string29 = /\\pwdump\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string30 = /\\Responder\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string31 = /\\SMB\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string32 = /\\SMB\-NTLMSSPv2\-Client\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string33 = /\\SMB\-NTLMv1\-Client\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string34 = /\\SMBRelay\-Session\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string35 = /\\SMTP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string36 = /\\Windows\\Temp\\Results\.txt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string37 = /0fa31c8c34a370931d8ffe8097e998f778db63e2e036fbd7727a71a0dcf5d28c/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string38 = /3c6898fa2726b6487fcb12b854021b4e23f984e2bcdf5b5fe300c36cec2ad1a4/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string39 = /47d121087c05568fe90a25ef921f9e35d40bc6bec969e33e75337fc9b580f0e8/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string40 = /54a43829632b2b9984076cb2e24c2d4cbd5e50c410eb4320591e3fc347dec662/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string41 = /6a1d85188bb481088fdd202dbb994910de83b05a2b49420faf1dc4a66143918b/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string42 = /89c2214589dff9530c6367d2968ba26cd9533eb279b88dc755b06d66ed575428/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string43 = /BrowserListener\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string44 = /cert.{0,1000}responder\.crt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string45 = /cert.{0,1000}responder\.key/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string46 = /f2816b74ccb015b5eb7910f0ee389531ffaa0df8bc613d419cc4d4a50e99bb4e/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string47 = /f8a603588cb91acf4c4a745f74326d202f4d63243fefaf048e1076174a18a50a/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string48 = /files\/BindShell\.exe/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string49 = /files\/BindShell\.exe/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string50 = /FindSMB2UPTime\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string51 = /Icmp\-Redirect\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string52 = /lgandx\/Responder\-Windows/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string53 = /LLMNR\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string54 = /MIIEowIBAAKCAQEAunMwNRcEEAUJQSZDeDh\/hGmpPEzMr1v9fVYie4uFD33thh1k/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string55 = /netsh\sfirewall\sset\sopmode\sdisable/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string56 = /Poisoners\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string57 = /Preparing\sWindows\sfor\sResponder\.\.\.\\nDisabling\sNetBIOS/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string58 = /RelayPackets\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string59 = /responder\s.{0,1000}\s\-\-lm/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string60 = /responder\s\-i\s/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string61 = /Responder\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string62 = /Responder\\Responder\.exe/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string63 = /ResponderConfigDump\s/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string64 = /Responder\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string65 = /Responder\-Windows/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string66 = /SMBRelay\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string67 = /SpiderLabs\/Responder/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/lgandx/Responder-Windows/
        $string68 = /wmic\s\/interactive\:off\snicconfig\swhere\sTcpipNetbiosOptions\=0\scall\sSetTcpipNetbios\s2/ nocase ascii wide

    condition:
        any of them
}
