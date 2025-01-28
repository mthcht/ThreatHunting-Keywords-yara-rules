rule PowerUpSQL
{
    meta:
        description = "Detection patterns for the tool 'PowerUpSQL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerUpSQL"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string1 = " evil_DDL_trigger" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string2 = /\sFROM\sdbo\.C2Agents/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string3 = " -Name Publisher -Value \"Bad Person\"" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string4 = " -Name SQLC2AgentPS " nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\sPowerUpSQL\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string6 = /\sSQLC2\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string7 = " -TaskName \"SQLC2AgentPS" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string8 = /\sUPDATE\sdbo\.C2Agents/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string9 = " WHERE TABLE_NAME like 'C2AGENTS'" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string10 = " WHERE TABLE_NAME like 'C2COMMANDS'" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string11 = /\$SQLC2Command/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string12 = /\/PowerUpSQL\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string13 = /\/SQLC2\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string14 = /\:\\windows\\temp\\blah\.txt/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string15 = /\[SQLC2\sAgent\sJob\]/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string16 = /\\Backdoor\.exe/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string17 = /\\evil32\.dll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string18 = /\\evil64\.dll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string19 = /\\Get\-Credential\.sql/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string20 = /\\PowerUpSQL\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string21 = /\\SQLC2\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string22 = /\\SQLC2CMDS\.dll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string23 = /\\Windows\\CurrentVersion\\Uninstall\\SQLC2AgentPS/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string24 = /\\xp_evil_template\.cpp/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string25 = "<H1>PowerUp report for " nocase ascii wide
        // Description: NetSPI powershell modules to gather credentials
        // Reference: https://github.com/NetSPI/Powershell-Modules
        $string26 = "261a0287a47dd71f44a4494a5d563bd5aa673687f60744ecf559ecb817a7ac82" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string27 = /C\:\\temp\\iamahacker\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string28 = /c\:\\windows\\temp\\blah\.txt/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string29 = "Create-SQLFileCLRDll" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string30 = "Create-SQLFileXpDll" nocase ascii wide
        // Description: NetSPI powershell modules to gather credentials
        // Reference: https://github.com/NetSPI/Powershell-Modules
        $string31 = "d090bea299c6fb0956ce4a6450d0bfe1e3e0aa952a67b718f26e3668e41aac56" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string32 = /EXECUTE\(\'sp_configure\s\'\'xp_cmdshell\'\'\,1\;reconfigure\;\'/ nocase ascii wide
        // Description: NetSPI powershell modules to gather credentials
        // Reference: https://github.com/NetSPI/Powershell-Modules
        $string33 = "fcbcac521d37905835cbe924d2bca822513682a9cfa0d48945673e5b72d86709" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string34 = "Get-DomainSpn" nocase ascii wide
        // Description: NetSPI powershell modules to gather credentials
        // Reference: https://github.com/NetSPI/Powershell-Modules
        $string35 = "Get-MSSQLAllCredentials" nocase ascii wide
        // Description: NetSPI powershell modules to gather credentials
        // Reference: https://github.com/NetSPI/Powershell-Modules
        $string36 = "Get-MSSQLAllCredentials" nocase ascii wide
        // Description: NetSPI powershell modules to gather credentials
        // Reference: https://github.com/NetSPI/Powershell-Modules
        $string37 = "Get-MSSQLCredentialPasswords" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string38 = "Get-MSSQLCredentialPasswords" nocase ascii wide
        // Description: NetSPI powershell modules to gather credentials
        // Reference: https://github.com/NetSPI/Powershell-Modules
        $string39 = "Get-MSSQLLinkPasswords" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string40 = "Get-SQLC2Agent" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string41 = "Get-SQLC2Command " nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string42 = "Get-SQLC2ComputerNameFromInstance" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string43 = "Get-SQLC2Connection" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string44 = "Get-SQLC2Query" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string45 = "Get-SQLC2Result" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string46 = "Get-SQLDomainPasswordsLAPS" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string47 = "Get-SQLFuzzDatabaseName" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string48 = "Get-SQLFuzzDomainAccount" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string49 = "Get-SQLFuzzObjectName" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string50 = "Get-SQLFuzzServerLogin'" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string51 = "Get-SQLLocalAdminCheck" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string52 = "Get-SQLOleDbProvder" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string53 = "Get-SQLPersistRegDebugger" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string54 = "Get-SQLPersistRegRun" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string55 = "Get-SQLPersistTriggerDDL" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string56 = "Get-SQLRecoverPwAutoLogon" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string57 = "Get-SQLServerCredential" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string58 = "Get-SQLServerLinkCrawl" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string59 = "Get-SQLServerLoginDefaultPw" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string60 = "Get-SQLServerPasswordHash" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string61 = "Get-SQLServerPriv" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string62 = "Get-SQLServiceAccount" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string63 = "Get-SQLServiceAccountPwHashes" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string64 = "Get-SQLSysadminCheck" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string65 = "Get-SQLTriggerDdl" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string66 = "Get-SQLTriggerDml" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string67 = "Install-SQLC2AgentLink" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string68 = "Install-SQLC2Server" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string69 = /Inveigh\-BruteForce\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string70 = "Invoke-SQLAuditDefaultLoginPw" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string71 = "Invoke-SQLAuditPrivAutoExecSp" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string72 = "Invoke-SQLAuditPrivCreateProcedure" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string73 = "Invoke-SQLAuditPrivDbChaining" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string74 = "Invoke-SQLAuditPrivImpersonateLogin" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string75 = "Invoke-SQLAuditPrivServerLink" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string76 = "Invoke-SQLAuditPrivTrustworthy" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string77 = "Invoke-SQLAuditPrivXpDirtree" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string78 = "Invoke-SQLAuditPrivXpFileexit" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string79 = "Invoke-SQLAuditSQLiSpExecuteAs" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string80 = "Invoke-SQLAuditSQLiSpSigned" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string81 = "Invoke-SQLAuditWeakLoginPw" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string82 = "Invoke-SQLC2Command" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string83 = "Invoke-SQLDumpInfo" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string84 = "Invoke-SQLEscalatePriv" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string85 = "Invoke-SQLImpersonateService" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string86 = "Invoke-SQLImpersonateServiceCmd" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string87 = "Invoke-SQLOSCmd" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string88 = "Invoke-SQLOSCmdAgentJob" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string89 = "Invoke-SQLOSCmdCLR" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string90 = "Invoke-SQLOSCmdCOle" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string91 = "Invoke-SQLOSCmdPython" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string92 = "Invoke-SQLOSCmdR" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string93 = "Invoke-SqlServer-Persist-StartupSp" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string94 = "Invoke-SqlServer-Persist-TriggerLogon" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string95 = "Invoke-SQLUncPathInjection" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string96 = "Invoke-SQLUncPathInjection" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string97 = "Invoke-TokenManipulation" nocase ascii wide
        // Description: NetSPI powershell modules to gather credentials
        // Reference: https://github.com/NetSPI/Powershell-Modules
        $string98 = "NetSPI/Powershell-Modules" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string99 = /New\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\UtilMan\.exe\\"\s\-Name\s/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string100 = "PowerUpSQL" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string101 = "Register-SQLC2Agent" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string102 = "Remove-SQLC2Agent" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string103 = "Remove-SQLC2Command" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string104 = /SQLC2CMDS\.dll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string105 = "Uninstall-SQLC2AgentPs" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string106 = "Uninstall-SQLC2Server" nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string107 = /writefile_bcpxpcmdshell\.sql/ nocase ascii wide

    condition:
        any of them
}
