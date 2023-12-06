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
        $string1 = /\sCred_Dump\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string2 = /\sDefense_Evasion\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string3 = /\sExfil\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string4 = /\sHak5\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string5 = /\sPersistence\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string6 = /\sPriv_Esc\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string7 = /\.\/Exfil\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string8 = /\.\/Phishing\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string9 = /\/Cred_Dump\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string10 = /\/Defense_Evasion\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string11 = /\/Hak5\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string12 = /\/opt\/Password_Cracking\// nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string13 = /\/Persistence\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string14 = /\/Phishing\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string15 = /\/Priv_Esc\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string16 = /AutoC2\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string17 = /AutoC2\/All\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string18 = /AutoC2\/C2/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string19 = /AutoC2\/Dependencies/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string20 = /AutoC2\/Initial_Access/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string21 = /AutoC2\/Lateral\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string22 = /AutoC2\/Payload_Development/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string23 = /AutoC2\/Recon/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string24 = /AutoC2\/Situational_Awareness/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string25 = /AutoC2\/Social\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string26 = /AutoC2\/Staging/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string27 = /AutoC2\/Web\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string28 = /AutoC2\/Wireless\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string29 = /AutoC2\/Wordlists/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string30 = /Password_Cracking\.sh/ nocase ascii wide

    condition:
        any of them
}
