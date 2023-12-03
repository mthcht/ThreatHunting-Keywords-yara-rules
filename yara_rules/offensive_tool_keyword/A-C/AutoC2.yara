rule AutoC2
{
    meta:
        description = "Detection patterns for the tool 'AutoC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string1 = /.{0,1000}\sCred_Dump\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string2 = /.{0,1000}\sDefense_Evasion\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string3 = /.{0,1000}\sExfil\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string4 = /.{0,1000}\sHak5\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string5 = /.{0,1000}\sPersistence\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string6 = /.{0,1000}\sPriv_Esc\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string7 = /.{0,1000}\.\/Exfil\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string8 = /.{0,1000}\.\/Phishing\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string9 = /.{0,1000}\/Cred_Dump\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string10 = /.{0,1000}\/Defense_Evasion\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string11 = /.{0,1000}\/Hak5\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string12 = /.{0,1000}\/opt\/Password_Cracking\/.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string13 = /.{0,1000}\/Persistence\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string14 = /.{0,1000}\/Phishing\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string15 = /.{0,1000}\/Priv_Esc\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string16 = /.{0,1000}AutoC2\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string17 = /.{0,1000}AutoC2\/All\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string18 = /.{0,1000}AutoC2\/C2.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string19 = /.{0,1000}AutoC2\/Dependencies.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string20 = /.{0,1000}AutoC2\/Initial_Access.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string21 = /.{0,1000}AutoC2\/Lateral\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string22 = /.{0,1000}AutoC2\/Payload_Development.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string23 = /.{0,1000}AutoC2\/Recon.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string24 = /.{0,1000}AutoC2\/Situational_Awareness.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string25 = /.{0,1000}AutoC2\/Social\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string26 = /.{0,1000}AutoC2\/Staging.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string27 = /.{0,1000}AutoC2\/Web\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string28 = /.{0,1000}AutoC2\/Wireless\.sh.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string29 = /.{0,1000}AutoC2\/Wordlists.{0,1000}/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string30 = /.{0,1000}Password_Cracking\.sh.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
