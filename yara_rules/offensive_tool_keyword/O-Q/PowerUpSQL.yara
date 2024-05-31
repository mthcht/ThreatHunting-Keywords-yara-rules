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
        $string1 = /\sevil_DDL_trigger/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string2 = /\sFROM\sdbo\.C2Agents/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string3 = /\s\-Name\sPublisher\s\-Value\s\"Bad\sPerson\"/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string4 = /\s\-Name\sSQLC2AgentPS\s/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string5 = /\sSQLC2\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string6 = /\s\-TaskName\s\"SQLC2AgentPS/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string7 = /\sUPDATE\sdbo\.C2Agents/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string8 = /\sWHERE\sTABLE_NAME\slike\s\'C2AGENTS\'/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string9 = /\sWHERE\sTABLE_NAME\slike\s\'C2COMMANDS\'/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string10 = /\$SQLC2Command/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string11 = /\/SQLC2\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string12 = /\:\\windows\\temp\\blah\.txt/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string13 = /\[SQLC2\sAgent\sJob\]/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string14 = /\\Backdoor\.exe/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string15 = /\\evil32\.dll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string16 = /\\evil64\.dll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string17 = /\\Get\-Credential\.sql/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string18 = /\\SQLC2\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string19 = /\\SQLC2CMDS\.dll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string20 = /\\Windows\\CurrentVersion\\Uninstall\\SQLC2AgentPS/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string21 = /\\xp_evil_template\.cpp/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string22 = /C\:\\temp\\iamahacker\.txt/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string23 = /Create\-SQLFileCLRDll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string24 = /Create\-SQLFileXpDll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string25 = /EXECUTE\(\'sp_configure\s\'\'xp_cmdshell\'\'\,1\;reconfigure\;\'/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string26 = /Get\-DomainSpn/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string27 = /Get\-MSSQLCredentialPasswords/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string28 = /Get\-SQLC2Agent/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string29 = /Get\-SQLC2Command\s/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string30 = /Get\-SQLC2ComputerNameFromInstance/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string31 = /Get\-SQLC2Connection/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string32 = /Get\-SQLC2Query/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string33 = /Get\-SQLC2Result/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string34 = /Get\-SQLDomainPasswordsLAPS/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string35 = /Get\-SQLFuzzDatabaseName/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string36 = /Get\-SQLFuzzDomainAccount/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string37 = /Get\-SQLFuzzObjectName/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string38 = /Get\-SQLFuzzServerLogin\'/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string39 = /Get\-SQLLocalAdminCheck/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string40 = /Get\-SQLOleDbProvder/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string41 = /Get\-SQLPersistRegDebugger/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string42 = /Get\-SQLPersistRegRun/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string43 = /Get\-SQLPersistTriggerDDL/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string44 = /Get\-SQLRecoverPwAutoLogon/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string45 = /Get\-SQLServerCredential/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string46 = /Get\-SQLServerLinkCrawl/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string47 = /Get\-SQLServerLoginDefaultPw/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string48 = /Get\-SQLServerPasswordHash/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string49 = /Get\-SQLServerPriv/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string50 = /Get\-SQLServiceAccount/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string51 = /Get\-SQLServiceAccountPwHashes/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string52 = /Get\-SQLSysadminCheck/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string53 = /Get\-SQLTriggerDdl/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string54 = /Get\-SQLTriggerDml/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string55 = /Install\-SQLC2AgentLink/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string56 = /Install\-SQLC2Server/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string57 = /Inveigh\-BruteForce\.ps1/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string58 = /Invoke\-SQLAuditDefaultLoginPw/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string59 = /Invoke\-SQLAuditPrivAutoExecSp/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string60 = /Invoke\-SQLAuditPrivCreateProcedure/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string61 = /Invoke\-SQLAuditPrivDbChaining/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string62 = /Invoke\-SQLAuditPrivImpersonateLogin/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string63 = /Invoke\-SQLAuditPrivServerLink/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string64 = /Invoke\-SQLAuditPrivTrustworthy/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string65 = /Invoke\-SQLAuditPrivXpDirtree/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string66 = /Invoke\-SQLAuditPrivXpFileexit/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string67 = /Invoke\-SQLAuditSQLiSpExecuteAs/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string68 = /Invoke\-SQLAuditSQLiSpSigned/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string69 = /Invoke\-SQLAuditWeakLoginPw/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string70 = /Invoke\-SQLC2Command/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string71 = /Invoke\-SQLDumpInfo/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string72 = /Invoke\-SQLEscalatePriv/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string73 = /Invoke\-SQLImpersonateService/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string74 = /Invoke\-SQLImpersonateServiceCmd/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string75 = /Invoke\-SQLOSCmd/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string76 = /Invoke\-SQLOSCmdAgentJob/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string77 = /Invoke\-SQLOSCmdCLR/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string78 = /Invoke\-SQLOSCmdCOle/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string79 = /Invoke\-SQLOSCmdPython/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string80 = /Invoke\-SQLOSCmdR/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string81 = /Invoke\-SqlServer\-Persist\-StartupSp/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string82 = /Invoke\-SqlServer\-Persist\-TriggerLogon/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string83 = /Invoke\-SQLUncPathInjection/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string84 = /Invoke\-SQLUncPathInjection/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string85 = /Invoke\-TokenManipulation/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string86 = /New\-ItemProperty\s\-Path\s\"HKLM\:\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\UtilMan\.exe\"\s\-Name\s/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string87 = /PowerUpSQL/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string88 = /Register\-SQLC2Agent/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string89 = /Remove\-SQLC2Agent/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string90 = /Remove\-SQLC2Command/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string91 = /SQLC2CMDS\.dll/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string92 = /Uninstall\-SQLC2AgentPs/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string93 = /Uninstall\-SQLC2Server/ nocase ascii wide
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string94 = /writefile_bcpxpcmdshell\.sql/ nocase ascii wide

    condition:
        any of them
}
