rule CheeseTools
{
    meta:
        description = "Detection patterns for the tool 'CheeseTools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheeseTools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string1 = /\s\-\-am\-si\-bypass\=/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string2 = /\s\-\-reflective\-injection\s/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string3 = /\s\-\-wldp\-bypass\=/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string4 = /\/CheeseTools\.git/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string5 = /0DD419E5\-D7B3\-4360\-874E\-5838A7519355/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string6 = /36F9C306\-5F45\-4946\-A259\-610C05BD90DF/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string7 = /A8FE1F5C\-6B2A\-4417\-907F\-4F6EDE9C15A3/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string8 = /AmsiBypass\.cs/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string9 = /AS\s\'Login\sthat\scan\sbe\simpersonated\'/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string10 = /as\s\'Owner\sthat\scan\sbe\simpersonated\'/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string11 = /C\:\\Users\\Public\\perm\.txt/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string12 = /C\:\\Users\\Public\\test\.txt/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string13 = /C526B877\-6AFF\-413C\-BC03\-1837FB63BC22/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string14 = /CD3578F6\-01B7\-48C9\-9140\-1AFA44B3A7C0/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string15 = /CheeseDCOM\.exe/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string16 = /CheeseExec\.csproj/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string17 = /CheeseExec\.exe/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string18 = /CheesePS\.csproj/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string19 = /CheesePS\.exe/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string20 = /CheeseRDP\.exe/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string21 = /CheeseSQL\.exe/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string22 = /CheeseTools\.sln/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string23 = /CheeseTools\-master/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string24 = /klezVirus\/CheeseTools/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string25 = /SELECT\sSYSTEM_USER\sas\s\'Logged\sin\sas\'.{0,1000}\sCURRENT_USER\sas\s\'Mapped\sas\'/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string26 = /WldpBypass\.cs/ nocase ascii wide

    condition:
        any of them
}
