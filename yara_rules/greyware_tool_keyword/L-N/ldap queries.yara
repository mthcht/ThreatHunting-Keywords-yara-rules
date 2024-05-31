rule ldap_queries
{
    meta:
        description = "Detection patterns for the tool 'ldap queries' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldap queries"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: metasploit enum_ad_user_comments
        // Reference: https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726
        $string1 = /\(\&\(\&\(objectCategory\=person\)\(objectClass\=user\)\)\(\|\(description\=.{0,1000}pass.{0,1000}\)\(comment\=.{0,1000}pass.{0,1000}\)\)\)/ nocase ascii wide
        // Description: Enumerate Read-Only Domain Controllers (RODC)
        // Reference: https://github.com/mthcht/ThreatHunting-Keywords
        $string2 = /\(\&\(objectCategory\=computer\)\(msDS\-isRODC\=TRUE\)\)/ nocase ascii wide
        // Description: LAPS passwords (from SharpLAPS)
        // Reference: https://gist.github.com/jsecurity101/9c7e94f95b8d90f9252d64949562ba5d
        $string3 = /\(\&\(objectCategory\=computer\)\(ms\-MCS\-AdmPwd\=.{0,1000}\)\(sAMAccountName\=\"\s\+\starget\s\+\s\"\)\)/ nocase ascii wide
        // Description: Enumerate Accounts with Non-Expiring Passwords and Administrative Privileges
        // Reference: https://github.com/mthcht/ThreatHunting-Keywords
        $string4 = /\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=65536\)\(memberOf\=CN\=Administrators/ nocase ascii wide
        // Description: Enumerate all users with the account configuration 'Password never expires'
        // Reference: https://gist.github.com/jsecurity101/9c7e94f95b8d90f9252d64949562ba5d
        $string5 = /\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=65536\)/ nocase ascii wide
        // Description: metasploit  enum_ad_managedby_groups.rb
        // Reference: https://github.com/rapid7/metasploit-framework/blob/d37a82500d1d08f9d8ab3da9b194653835748fae/modules/post/windows/gather/enum_ad_managedby_groups.rb#L59
        $string6 = /\(\&\(objectClass\=group\)\(managedBy\=.{0,1000}\)\(groupType\:1\.2\.840\.113556\.1\.4\.803\:\=2147483648\)\)/ nocase ascii wide
        // Description: Enumerate Domain Administrators Group
        // Reference: https://jsecurity101.medium.com/uncovering-adversarial-ldap-tradecraft-658b2deca384
        $string7 = /\(\&\(objectclass\=group\)\(samaccountname\=.{0,1000}domain\sadmins.{0,1000}\)\)/ nocase ascii wide
        // Description: Kerberoasting
        // Reference: https://gist.github.com/jsecurity101/9c7e94f95b8d90f9252d64949562ba5d
        $string8 = /\(\&\(samAccountType\=805306368\)\(servicePrincipalName\=.{0,1000}\)\(\!samAccountName\=krbtgt\)\(\!\(UserAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\(\!msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.804\:\=24\)\)/ nocase ascii wide
        // Description: Kerberoasting
        // Reference: https://gist.github.com/jsecurity101/9c7e94f95b8d90f9252d64949562ba5d
        $string9 = /\(\&\(samAccountType\=805306368\)\(servicePrincipalName\=.{0,1000}\)\(\!samAccountName\=krbtgt\)\(\!\(UserAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\(msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.804\:\=24\)\)/ nocase ascii wide
        // Description: Kerberoasting
        // Reference: https://gist.github.com/jsecurity101/9c7e94f95b8d90f9252d64949562ba5d
        $string10 = /\(\&\(samAccountType\=805306368\)\(servicePrincipalName\=.{0,1000}\)\(\!samAccountName\=krbtgt\)\(\!\(UserAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\)/ nocase ascii wide
        // Description: Enumerate all servers configured for Unconstrained Delegation
        // Reference: N/A
        $string11 = /\(\[adsisearcher\]\'\(\&\(objectCategory\=computer\)\(\!\(primaryGroupID\=516\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)\)\)\'\)\.FindAll\(\)/ nocase ascii wide
        // Description: Enumerate all Domain Controllers
        // Reference: https://web.archive.org/web/20240109000256/https://cyberdom.blog/2024/01/07/defender-for-identity-hunting-for-ldap/
        $string12 = /\(\[adsisearcher\]\'\(\&\(objectCategory\=computer\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=8192\)\)\'\)\.FindAll\(\)/ nocase ascii wide
        // Description: Search for user accounts with SPN but not TGT accounts
        // Reference: https://jsecurity101.medium.com/uncovering-adversarial-ldap-tradecraft-658b2deca384
        $string13 = /\(\[adsisearcher\]\'\(\&\(objectCategory\=user\)\(\!\(samAccountName\=krbtgt\)\(servicePrincipalName\=.{0,1000}\)\)\)\'\)\.FindAll\(\)/ nocase ascii wide
        // Description: Search for all objects with AdminSHHolder
        // Reference: https://jsecurity101.medium.com/uncovering-adversarial-ldap-tradecraft-658b2deca384
        $string14 = /\(\[adsisearcher\]\'\(adminCount\=1\)\'\)\.FindAll\(\)/ nocase ascii wide
        // Description: Queries for domain level and mode information
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string15 = /\(\[DirectoryServices\.ActiveDirectory\.Forest\]\:\:GetCurrentForest\(\)\)\.Domains/ nocase ascii wide
        // Description: enumeration of AD Forest Sites
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string16 = /\(\[DirectoryServices\.ActiveDirectory\.Forest\]\:\:GetCurrentForest\(\)\)\.Sites\s\|\s/ nocase ascii wide
        // Description: querying all domain controllers with detailed properties
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string17 = /\(\[System\.DirectoryServices\.ActiveDirectory\.Domain\]\:\:GetCurrentDomain\(\)\)\.FindAllDomainControllers\(\)\s\|\sSelect\-Object\s\-Property\s/ nocase ascii wide
        // Description: get all trust relationships in the current domain
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string18 = /\(\[System\.DirectoryServices\.ActiveDirectory\.Domain\]\:\:GetCurrentDomain\(\)\)\.GetAllTrustRelationships\(\)/ nocase ascii wide
        // Description: Enumerate all of the domain controllers for all domains in a forest
        // Reference: N/A
        $string19 = /\(Get\-ADForest\)\.Domains\s\|\s\%\{\sGet\-ADDomainController\s\-Filter\s.{0,1000}\s\-Server\s\$_\s\}/ nocase ascii wide
        // Description: used by Rubeus and S4UTomato tools
        // Reference: N/A
        $string20 = /\(msds\-supportedencryptiontypes\=0\)\(msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.803\:\=4\)\)\)/ nocase ascii wide
        // Description: Query to find service accounts which are typically high-privileged and targeted for privilege escalation
        // Reference: https://github.com/mthcht/ThreatHunting-Keywords
        $string21 = /\(objectCategory\=person\)\(objectClass\=user\)\(serviceAccount\=TRUE\)/ nocase ascii wide
        // Description: Enumerate Domain Admins
        // Reference: https://gist.github.com/jsecurity101/9c7e94f95b8d90f9252d64949562ba5d
        $string22 = /\(objectclass\=group\)\(samaccountname\=domain\sadmins\)/ nocase ascii wide
        // Description: Accounts Trusted for Delegation
        // Reference: https://gist.github.com/jsecurity101/9c7e94f95b8d90f9252d64949562ba5d
        $string23 = /\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)/ nocase ascii wide
        // Description: enumeration of Domain Password Policies
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string24 = /\[ADSI\].{0,1000}\s\|\sSelect\-Object\s\-Property\s.{0,1000}lockoutDuration/ nocase ascii wide
        // Description: enumeration of Domain Password Policies
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string25 = /\[ADSI\].{0,1000}\s\|\sSelect\-Object\s\-Property\s.{0,1000}lockoutThreshold/ nocase ascii wide
        // Description: enumeration of Domain Password Policies
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string26 = /\[ADSI\].{0,1000}\s\|\sSelect\-Object\s\-Property\s.{0,1000}minPwdLength/ nocase ascii wide
        // Description: enumeration of Domain Admins group members
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string27 = /\[ADSI\].{0,1000}LDAP\:\/\/CN\=Domain\sAdmins.{0,1000}\|\sForEach\-Object\s\{\[adsi\]\"LDAP\:\/\/\$_\"\}\;\s.{0,1000}\.distinguishedname/ nocase ascii wide
        // Description: get LDAP properties for password settings directly
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string28 = /\[ADSI\].{0,1000}LDAP\:\/\/dc\=.{0,1000}\s\|\sSelect\s\-Property\spwdProperties/ nocase ascii wide
        // Description: find user descriptions in Active Directory:
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string29 = /\[adsisearcher\]\"\(\&\(objectCategory\=person\)\(objectClass\=user\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\)\"\;\s\$users\s\=\s\$searchUsers\.FindAll\(\)\;\s\$userProps\s\=\s\$users\.Properties\;\s\$userProps\s\|\sWhere\-Object\s\{\$_\.description\}/ nocase ascii wide
        // Description: find all disabled user accounts
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string30 = /\[adsisearcher\]\"\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\"/ nocase ascii wide
        // Description: get a count of all inter domain trust accounts
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string31 = /\[adsisearcher\]\"\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2560\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\)\"/ nocase ascii wide
        // Description: Detection of all accounts with 'Password Not Required'
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string32 = /\[adsisearcher\]\"\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=32\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\)/ nocase ascii wide
        // Description: Enumerate all Domain Controllers
        // Reference: https://web.archive.org/web/20240109000256/https://cyberdom.blog/2024/01/07/defender-for-identity-hunting-for-ldap/
        $string33 = /\[adsisearcher\]\'\(\&\(objectCategory\=computer\)\(primaryGroupID\=516\)\)\'\)\.FindAll\(\)/ nocase ascii wide
        // Description: Enumerate all accounts that do not require a password
        // Reference: https://jsecurity101.medium.com/uncovering-adversarial-ldap-tradecraft-658b2deca384
        $string34 = /\[adsisearcher\]\'\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=32\)\)\'\)\.FindAll\(\)/ nocase ascii wide
        // Description: ADSI query to retrieve all active user accounts with non-expiring passwords
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string35 = /\[adsisearcher\].{0,1000}\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=66048\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)/ nocase ascii wide
        // Description: Discover all Domain Controller in the domain using ADSI
        // Reference: https://adsecurity.org/?p=299
        $string36 = /\[System\.DirectoryServices\.ActiveDirectory\.Domain\]\:\:GetCurrentDomain\(\)\.DomainControllers/ nocase ascii wide
        // Description: Discover all Global Catalogs in the forest using ADSI
        // Reference: https://adsecurity.org/?p=299
        $string37 = /\[System\.DirectoryServices\.ActiveDirectory\.Forest\]\:\:GetCurrentForest\(\)\.GlobalCatalogs/ nocase ascii wide
        // Description: query for the primary domain controller within the forest
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string38 = /\[System\.DirectoryServices\.ActiveDirectory\.Forest\]\:\:GetCurrentForest\(\)\.RootDomain\.PDCRoleOwner\.Name/ nocase ascii wide
        // Description: cmdlets to get computer information about Domain Controllers
        // Reference: https://adsecurity.org/?p=299
        $string39 = /get\-ADComputer\s\-filter\s\{\sPrimaryGroupID\s\-eq\s\"516\"\s\}\s\-properties\sPrimaryGroupID/ nocase ascii wide
        // Description: identifying accounts with 'Password Not Required
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string40 = /Get\-ADUser\s\-filter\s.{0,1000}\s\-Properties\sSamAccountName\,\sPasswordNotRequired\s\|\swhere\s\{\s\$_\.passwordnotrequired\s\-eq\s\"true\"\s\}\s\|\swhere\s\{\$_\.enabled\s\-eq\s\"true\"\}/ nocase ascii wide
        // Description: querying accounts that have not been logged into for over 90 days
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string41 = /Get\-ADUser\s\-properties\s.{0,1000}\s\-filter\s\{\(lastlogondate\s\-notlike\s\".{0,1000}\"\s\-OR\slastlogondate\s\-le\s\$90days\)\s\-AND\s\(passwordlastset\s\-le\s\$90days\)\s\-AND\s\(enabled\s\-eq\s\$True\)\s\-and\s\(PasswordNeverExpires\s\-eq\s\$false\)\s\-and\s\(whencreated\s\-le\s\$90days\)\}/ nocase ascii wide
        // Description: Red Teams and adversaries may leverage [Adsisearcher] to enumerate domain groups for situational awareness and Active Directory Discovery
        // Reference: https://research.splunk.com/endpoint/089c862f-5f83-49b5-b1c8-7e4ff66560c7/
        $string42 = /powershell.{0,1000}\[adsisearcher\].{0,1000}\(objectcategory\=group\).{0,1000}findAll\(\)/ nocase ascii wide

    condition:
        any of them
}
