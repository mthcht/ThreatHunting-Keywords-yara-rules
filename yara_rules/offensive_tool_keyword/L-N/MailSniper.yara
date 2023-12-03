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
        $string1 = /.{0,1000}\s\-ExchHostname\s.{0,1000}\s\-Password\s.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string2 = /.{0,1000}\s\-Remote\s\-ExchHostname\s.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string3 = /.{0,1000}\/MailSniper\/.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string4 = /.{0,1000}AccessTokenImpersonationAccount.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string5 = /.{0,1000}dafthack\/MailSniper.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string6 = /.{0,1000}Get\-AccessTokenWithPRT.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string7 = /.{0,1000}Get\-ADUsernameFromEWS.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string8 = /.{0,1000}Get\-BaseLineResponseTimeEAS.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string9 = /.{0,1000}Get\-ExchangeAccessToken.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string10 = /.{0,1000}Get\-ExoPsAccessToken.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string11 = /.{0,1000}Get\-HeadersWithPrtCookies.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string12 = /.{0,1000}Get\-UserPRTToken.{0,1000}/ nocase ascii wide
        // Description: Invoke-DomainHarvest* will attempt to connect to an * portal and determine a valid domain name for logging into the portal
        // Reference: https://github.com/dafthack/MailSniper
        $string13 = /.{0,1000}Invoke\-DomainHarvest.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string14 = /.{0,1000}Invoke\-DomainHarvestOWA.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string15 = /.{0,1000}Invoke\-GlobalMailSearch.{0,1000}/ nocase ascii wide
        // Description: To search all mailboxes in a domain
        // Reference: https://github.com/dafthack/MailSniper
        $string16 = /.{0,1000}Invoke\-GlobalMailSearch.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string17 = /.{0,1000}Invoke\-GlobalO365MailSearch.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string18 = /.{0,1000}Invoke\-InjectGEvent.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string19 = /.{0,1000}Invoke\-InjectGEventAPI.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string20 = /.{0,1000}Invoke\-MonitorCredSniper.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string21 = /.{0,1000}Invoke\-OpenInboxFinder.{0,1000}/ nocase ascii wide
        // Description: Invoke-PasswordSpray* will attempt to connect to an * portal and perform a password spraying attack using a userlist and a single password.
        // Reference: https://github.com/dafthack/MailSniper
        $string22 = /.{0,1000}Invoke\-PasswordSpray.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string23 = /.{0,1000}Invoke\-PasswordSprayEAS.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string24 = /.{0,1000}Invoke\-PasswordSprayEWS.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string25 = /.{0,1000}Invoke\-PasswordSprayGmail.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string26 = /.{0,1000}Invoke\-PasswordSprayOWA.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string27 = /.{0,1000}Invoke\-UsernameHarvestEAS.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string28 = /.{0,1000}Invoke\-UsernameHarvestGmail.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string29 = /.{0,1000}Invoke\-UsernameHarvestOWA.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string30 = /.{0,1000}LoadEWSDLL.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc...). It can be used as a non-administrative user to search their own email. or by an Exchange administrator to search the mailboxes of every user in a domain
        // Reference: https://github.com/dafthack/MailSniper
        $string31 = /.{0,1000}MailSniper.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string32 = /.{0,1000}MailSniper\.ps1.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string33 = /.{0,1000}UsePrtAdminAccount.{0,1000}/ nocase ascii wide
        // Description: MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords. insider intel. network architecture information. etc.). It can be used as a non-administrative user to search their own email. or by an administrator to search the mailboxes of every user in a domain.
        // Reference: https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
        $string34 = /.{0,1000}UsePrtImperonsationAccount.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
