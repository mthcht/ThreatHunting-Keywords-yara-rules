rule S4UTomato
{
    meta:
        description = "Detection patterns for the tool 'S4UTomato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S4UTomato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string1 = /\s\/s4uproxytarget\:.{0,100}\s\/s4utransitiedservices\:/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string2 = /\sYou\sneed\sto\shave\san\selevated\scontext\sto\sdump\sother\susers\'\sKerberos\stickets\s\:\(/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string3 = /\\"UACBypassedService\\"/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string4 = /\(msds\-supportedencryptiontypes\=0\)\(msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.803\:\=4\)\)\)/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string5 = /\.exe\skrbscm\s\-c\s.{0,100}cmd\.exe/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string6 = /\.exe\srbcd\s\-m\s.{0,100}\s\-p\s.{0,100}\s\-c\s.{0,100}cmd\.exe/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string7 = /\.exe\sshadowcred\s\-c\s.{0,100}\s\-f/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string8 = /\/ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string9 = /\/MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string10 = /\/S4UTomato\.git/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string11 = /\[\+\]\sAS\-REQ\sw\/o\spreauth\ssuccessful\!/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string12 = /\[\+\]\scross\srealm\sS4U2Self\ssuccess\!/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string13 = /\[\+\]\sS4U2proxy\ssuccess\!/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string14 = /\[\+\]\sS4U2self\ssuccess\!/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string15 = /\\ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string16 = /\\MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string17 = /\\S4U\.Exe/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string18 = /\\S4UTomato\\/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string19 = /\\ShadowCredentials\.cs/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string20 = /\\UACBypassedService/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string21 = /\]\sRetrieving\sthe\sS4U2Self\sreferral\sfrom\s/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string22 = /\]\sRoasted\shashes\swritten\sto\s\:\s/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string23 = /\]\sSending\sS4U2proxy\srequest\s/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string24 = /\>UACBypassedService\</ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string25 = /0cf16d4d70941be216c787a44a7401c9c9547016952a2c699579d4e4bb9c8110/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string26 = /3c3a96d02e34589d314b230c417b122970e492282767211866c8ac042e8bd556/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string27 = /881D4D67\-46DD\-4F40\-A813\-C9D3C8BE0965/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string28 = /bc25b38d07d2dbc8c7d9491a0779dcfaf87ea69ce078900ed61d307f45da33c3/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string29 = /localS4U2Proxy\.tickets/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string30 = /Run\sthe\skrbscm\smethod\sfor\sSYSTEM\sshell/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string31 = /S4UTomato\s1\.0\.0\-beta/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string32 = /S4UTomato\.csproj/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string33 = /S4UTomato\.exe/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string34 = /S4UTomato\.lib/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string35 = /S4UTomato\.sln/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string36 = /S4UTomato\-master/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string37 = /ShadowCredentials\.Execute\(/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string38 = /UserAgent\s\=\s\\"Rubeus\/1\.0\\"/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string39 = /wh0amitz\/S4UTomato/ nocase ascii wide
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
