rule MailSniper
{
    meta:
        description = "Detection patterns for the tool 'MailSniper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailSniper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string1 = /\s\-ExchHostname\s.{0,100}\s\-Password\s/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string2 = /\s\-Remote\s\-ExchHostname\s/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string3 = /\/MailSniper\// nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string4 = /AccessTokenImpersonationAccount/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string5 = /dafthack\/MailSniper/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string6 = /Get\-AccessTokenWithPRT/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string7 = /Get\-ADUsernameFromEWS/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string8 = /Get\-BaseLineResponseTimeEAS/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string9 = /Get\-ExchangeAccessToken/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string10 = /Get\-ExoPsAccessToken/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string11 = /Get\-HeadersWithPrtCookies/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string12 = /Get\-UserPRTToken/ nocase ascii wide
        // Description: Invoke-DomainHarvest* will attempt to connect to an * portal and determine a valid domain name for logging into the portal
        // Reference: https://github.com/dafthack/MailSniper
        $string13 = /Invoke\-DomainHarvest/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string14 = /Invoke\-DomainHarvestOWA/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string15 = /Invoke\-GlobalMailSearch/ nocase ascii wide
        // Description: To search all mailboxes in a domain
        // Reference: https://github.com/dafthack/MailSniper
        $string16 = /Invoke\-GlobalMailSearch/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string17 = /Invoke\-GlobalO365MailSearch/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string18 = /Invoke\-InjectGEvent/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string19 = /Invoke\-InjectGEventAPI/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string20 = /Invoke\-MonitorCredSniper/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string21 = /Invoke\-OpenInboxFinder/ nocase ascii wide
        // Description: Invoke-PasswordSpray* will attempt to connect to an * portal and perform a password spraying attack using a userlist and a single password.
        // Reference: https://github.com/dafthack/MailSniper
        $string22 = /Invoke\-PasswordSpray/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string23 = /Invoke\-PasswordSprayEAS/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string24 = /Invoke\-PasswordSprayEWS/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string25 = /Invoke\-PasswordSprayGmail/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string26 = /Invoke\-PasswordSprayOWA/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string27 = /Invoke\-UsernameHarvestEAS/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string28 = /Invoke\-UsernameHarvestGmail/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string29 = /Invoke\-UsernameHarvestOWA/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string30 = /LoadEWSDLL/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc...). It can be used as a non-administrative user to search their own email. or by an Exchange administrator to search the mailboxes of every user in a domain
        // Reference: https://github.com/dafthack/MailSniper
        $string31 = /MailSniper/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string32 = /MailSniper\.ps1/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string33 = /UsePrtAdminAccount/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string34 = /UsePrtImperonsationAccount/ nocase ascii wide
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
