rule covenant
{
    meta:
        description = "Detection patterns for the tool 'covenant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "covenant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string1 = /.{0,1000}\s\-\-name\scovenant\s.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string2 = /.{0,1000}\sstart\scovenant.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string3 = /.{0,1000}\sstop\scovenant.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string4 = /.{0,1000}\/Brute\/BruteStager.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string5 = /.{0,1000}\/BruteStager\.cs.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string6 = /.{0,1000}\/Covenant.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string7 = /.{0,1000}\/Covenant\.git.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string8 = /.{0,1000}\/Covenant\/.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string9 = /.{0,1000}\/CovenantUsers\/.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string10 = /.{0,1000}\/Elite\/Elite.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string11 = /.{0,1000}\/GruntHTTP\.exe.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string12 = /.{0,1000}\/Models\/PowerShellLauncher\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string13 = /.{0,1000}\/Models\/Regsvr32Launcher\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string14 = /.{0,1000}\/Models\/ShellCodeLauncher\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string15 = /.{0,1000}\/opt\/Covenant\/Covenant\/.{0,1000}/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string16 = /.{0,1000}\/SharpDump.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string17 = /.{0,1000}\/SharpSploit.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string18 = /.{0,1000}\/WhoAmI\.task.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string19 = /.{0,1000}\\Elite\.csproj.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string20 = /.{0,1000}\\Elite\.sln.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string21 = /.{0,1000}Brute\/Brute\.cs.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string22 = /.{0,1000}Brute\/Brute\.csproj.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string23 = /.{0,1000}Brute\/Brute\.sln.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string24 = /.{0,1000}BruteStager\.csproj.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string25 = /.{0,1000}BruteStager\.sln.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string26 = /.{0,1000}CapturedCredential\.cs.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string27 = /.{0,1000}CapturedCredential\.exe.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string28 = /.{0,1000}CapturedHashCredential\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string29 = /.{0,1000}CapturedPasswordCredential\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string30 = /.{0,1000}CapturedTicketCredential\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string31 = /.{0,1000}cobbr\/Covenant.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string32 = /.{0,1000}cobbr\/Elite.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string33 = /.{0,1000}Covenant\.API.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string34 = /.{0,1000}Covenant\.csproj.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string35 = /.{0,1000}Covenant\.exe.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string36 = /.{0,1000}Covenant\.Models.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string37 = /.{0,1000}Covenant\.sln.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string38 = /.{0,1000}Covenant\/Covenant.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string39 = /.{0,1000}Covenant\/wwwroot.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string40 = /.{0,1000}CovenantAPI\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string41 = /.{0,1000}CovenantAPIExtensions\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string42 = /.{0,1000}CovenantBaseMenuItem\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string43 = /.{0,1000}CovenantService\.cs.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string44 = /.{0,1000}CovenantUser\.cs.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string45 = /.{0,1000}CovenantUserLogin\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string46 = /.{0,1000}CovenantUserLoginResult\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string47 = /.{0,1000}CovenantUserRegister\..{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string48 = /.{0,1000}docker\s.{0,1000}\scovenant.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string49 = /.{0,1000}docker\s.{0,1000}\s\-\-name\selite\s.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string50 = /.{0,1000}docker\s.{0,1000}\s\-t\selite\s.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string51 = /.{0,1000}donut\-loader\s\-.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string52 = /.{0,1000}donut\-maker\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string53 = /.{0,1000}donut\-shellcode.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string54 = /.{0,1000}GruntInjection\.exe.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string55 = /.{0,1000}gruntstager\.cs.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string56 = /.{0,1000}GruntStager\.exe.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string57 = /.{0,1000}http.{0,1000}127\.0\.0\.1:57230.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string58 = /.{0,1000}http.{0,1000}localhost:57230.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string59 = /.{0,1000}https:\/\/127\.0\.0\.1:7443.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string60 = /.{0,1000}https:\/\/localhost:7443\/.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string61 = /.{0,1000}obfuscate\.py\sgrunt.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string62 = /.{0,1000}powerkatz_x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string63 = /.{0,1000}powerkatz_x86\.dll.{0,1000}/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string64 = /.{0,1000}SharpUp\saudit.{0,1000}/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string65 = /.{0,1000}ShellCmd\scmd\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string66 = /.{0,1000}ShellCmd\scopy\s.{0,1000}/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string67 = /.{0,1000}ShellCmd\snet\s.{0,1000}/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string68 = /.{0,1000}ShellCmd\ssc\sqc\s.{0,1000}/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string69 = /BypassUAC\s.{0,1000}/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string70 = /ShellCmd\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
