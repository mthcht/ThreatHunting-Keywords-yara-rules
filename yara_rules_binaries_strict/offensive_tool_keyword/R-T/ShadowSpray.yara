rule ShadowSpray
{
    meta:
        description = "Detection patterns for the tool 'ShadowSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string1 = " - ShadowSpray" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string2 = " --RestoreShadowCred" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string3 = /\/ShadowSpray\.git/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string4 = /\/ShadowSpray\.git/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string5 = /\/ShadowSpray\/.{0,100}\.cs/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string6 = /\[\!\]\sUnhandled\sShadowSpray\.Kerb\sexception\:/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string7 = /\[\+\]\sAttack\saborted\.\sExiting/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string8 = /\[\+\]\sGetting\scredentials\susing\sU2U/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string9 = /\[\+\]\sImporting\sticket\sinto\sa\ssacrificial\sprocess\susing\sCreateNetOnly/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string10 = /\[\+\]\sPerforming\srecursive\sShadowSpray\sattack\.\sThis\smight\stake\sa\swhile/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string11 = /\[\+\]\sShadowSpray\srecovered\s/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string12 = /\\ShadowSpray\.cs/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string13 = /\\ShadowSpray\.sln/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string14 = /\\ShadowSpray\\.{0,100}\.cs/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string15 = "1b6d6a1a116e8ddaeb7e3dde5dfc285e50004be80e977aa612447275c5930281" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string16 = "2fd04964c571de856492e42f27043367c4b8e452a7f4719a1bdb0470b2b6576c" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string17 = "7E47D586-DDC6-4382-848C-5CF0798084E1" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string18 = "7E47D586-DDC6-4382-848C-5CF0798084E1" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string19 = "837f6333561b575fc379d692f6f197a375feabb6c942170e262d36ef21709325" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string20 = /attacker\.shadowCredObjects\.Count/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string21 = "CN=ShadowSpray" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string22 = "Dec0ne/ShadowSpray" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string23 = /Options\.shadowCredCertificatePassword/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string24 = "Performing recursive ShadowSpray attack" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string25 = /shadowCredObject\.NTHash/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string26 = /shadowCredObject\.samAccountName/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string27 = "ShadowSpray recovered" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string28 = /ShadowSpray\.Asn1/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string29 = /ShadowSpray\.exe/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string30 = /ShadowSpray\.exe/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string31 = /ShadowSpray\.Kerb/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/Dec0ne/ShadowSpray
        $string32 = /ShadowSpray\.Kerb\/1\.0/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string33 = /ShadowSpray\.sln/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string34 = "ShadowSpray-master" nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string35 = "ShorSec/ShadowSpray" nocase ascii wide
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
