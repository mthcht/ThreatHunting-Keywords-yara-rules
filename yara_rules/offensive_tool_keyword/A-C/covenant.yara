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
        $string1 = /\s\-\-name\scovenant\s/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string2 = /\sstart\scovenant/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string3 = /\sstop\scovenant/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string4 = /\/Brute\/BruteStager/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string5 = /\/BruteStager\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string6 = /\/Covenant.{0,1000}\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string7 = /\/Covenant\.git/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string8 = /\/Covenant\// nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string9 = /\/CovenantUsers\// nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string10 = /\/Elite\/Elite/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string11 = /\/GruntHTTP\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string12 = /\/Models\/PowerShellLauncher\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string13 = /\/Models\/Regsvr32Launcher\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string14 = /\/Models\/ShellCodeLauncher\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string15 = /\/opt\/Covenant\/Covenant\// nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string16 = /\/SharpDump/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string17 = /\/SharpSploit/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string18 = /\/WhoAmI\.task/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string19 = /\\Elite\.csproj/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string20 = /\\Elite\.sln/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string21 = /Brute\/Brute\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string22 = /Brute\/Brute\.csproj/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string23 = /Brute\/Brute\.sln/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string24 = /BruteStager\.csproj/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string25 = /BruteStager\.sln/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string26 = /CapturedCredential\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string27 = /CapturedCredential\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string28 = /CapturedHashCredential\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string29 = /CapturedPasswordCredential\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string30 = /CapturedTicketCredential\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string31 = /cobbr\/Covenant/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string32 = /cobbr\/Elite/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string33 = /Covenant\.API/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string34 = /Covenant\.csproj/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string35 = /Covenant\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string36 = /Covenant\.Models/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string37 = /Covenant\.sln/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string38 = /Covenant\/Covenant/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string39 = /Covenant\/wwwroot/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string40 = /CovenantAPI\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string41 = /CovenantAPIExtensions\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string42 = /CovenantBaseMenuItem\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string43 = /CovenantService\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string44 = /CovenantUser\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string45 = /CovenantUserLogin\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string46 = /CovenantUserLoginResult\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string47 = /CovenantUserRegister\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string48 = /docker\s.{0,1000}\scovenant/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string49 = /docker\s.{0,1000}\s\-\-name\selite\s/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string50 = /docker\s.{0,1000}\s\-t\selite\s/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string51 = /donut\-loader\s\-/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string52 = /donut\-maker\.py\s\-/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string53 = /donut\-shellcode/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string54 = /GruntInjection\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string55 = /gruntstager\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string56 = /GruntStager\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string57 = /http.{0,1000}127\.0\.0\.1\:57230/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string58 = /http.{0,1000}localhost\:57230/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string59 = /https\:\/\/127\.0\.0\.1\:7443/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string60 = /https\:\/\/localhost\:7443\// nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string61 = /obfuscate\.py\sgrunt/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string62 = /powerkatz_x64\.dll/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string63 = /powerkatz_x86\.dll/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string64 = /SharpUp\saudit/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string65 = /ShellCmd\scmd\.exe\s/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string66 = /ShellCmd\scopy\s/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string67 = /ShellCmd\snet\s/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string68 = /ShellCmd\ssc\sqc\s/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string69 = /BypassUAC\s/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string70 = /ShellCmd\s/ nocase ascii wide

    condition:
        any of them
}
