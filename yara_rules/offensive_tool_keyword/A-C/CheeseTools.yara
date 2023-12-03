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
        $string1 = /.{0,1000}\s\-\-am\-si\-bypass\=.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string2 = /.{0,1000}\s\-\-reflective\-injection\s.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string3 = /.{0,1000}\s\-\-wldp\-bypass\=.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string4 = /.{0,1000}\/CheeseTools\.git.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string5 = /.{0,1000}0DD419E5\-D7B3\-4360\-874E\-5838A7519355.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string6 = /.{0,1000}36F9C306\-5F45\-4946\-A259\-610C05BD90DF.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string7 = /.{0,1000}A8FE1F5C\-6B2A\-4417\-907F\-4F6EDE9C15A3.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string8 = /.{0,1000}AmsiBypass\.cs.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string9 = /.{0,1000}AS\s\'Login\sthat\scan\sbe\simpersonated\'.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string10 = /.{0,1000}as\s\'Owner\sthat\scan\sbe\simpersonated\'.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string11 = /.{0,1000}C:\\Users\\Public\\perm\.txt.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string12 = /.{0,1000}C:\\Users\\Public\\test\.txt.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string13 = /.{0,1000}C526B877\-6AFF\-413C\-BC03\-1837FB63BC22.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string14 = /.{0,1000}CD3578F6\-01B7\-48C9\-9140\-1AFA44B3A7C0.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string15 = /.{0,1000}CheeseDCOM\.exe.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string16 = /.{0,1000}CheeseExec\.csproj.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string17 = /.{0,1000}CheeseExec\.exe.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string18 = /.{0,1000}CheesePS\.csproj.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string19 = /.{0,1000}CheesePS\.exe.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string20 = /.{0,1000}CheeseRDP\.exe.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string21 = /.{0,1000}CheeseSQL\.exe.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string22 = /.{0,1000}CheeseTools\.sln.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string23 = /.{0,1000}CheeseTools\-master.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string24 = /.{0,1000}klezVirus\/CheeseTools.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string25 = /.{0,1000}SELECT\sSYSTEM_USER\sas\s\'Logged\sin\sas\'.{0,1000}\sCURRENT_USER\sas\s\'Mapped\sas\'.{0,1000}/ nocase ascii wide
        // Description: tools for Lateral Movement/Code Execution
        // Reference: https://github.com/klezVirus/CheeseTools
        $string26 = /.{0,1000}WldpBypass\.cs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
