rule Jasmin_Ransomware
{
    meta:
        description = "Detection patterns for the tool 'Jasmin-Ransomware' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jasmin-Ransomware"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string1 = /\s\-u\sjasminadmin\s\-p.{0,1000}\sjasmin_db\s/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string2 = /\"handshake\"\,\s\"jasmin\@123\"/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string3 = /\.500\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string4 = /\.docx\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string5 = /\.jpeg\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string6 = /\.jpg\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string7 = /\.pdf\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string8 = /\.png\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string9 = /\.pptx\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string10 = /\.txt\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string11 = /\.xlsx\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string12 = /\/jasmin\-ransomware\.git/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string13 = /\\Jasmin\sDecryptor\\/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string14 = /\\Jasmin\sDecryptor\\/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string15 = /\\unlock\syour\sfiles\.lnk/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string16 = /\\Users\\Public\\Windows\\Ui/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string17 = /\\Users\\Public\\Windows\\Ui\\/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string18 = /\\Windows\\Ui\\index\.html/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string19 = /\>\-Infected\sSystems\sDatabase\-\<\/span\>/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string20 = /\>Jasmin\sRansomware\<\/div\>/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string21 = /6FF9974C\-B3C6\-4EEA\-8472\-22BE6BD6F5CD/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string22 = /78C76961\-8249\-4EFE\-9DE2\-B6EF15A187F7/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string23 = /C\:\\\\Users\\\\Public\\\\Windows\\\\Ui\\\\/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string24 = /codesiddhant\/jasmin\-ransomware/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string25 = /ConsoleHost_history\.txt\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string26 = /CREATE\sDATABASE\sjasmin_db/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string27 = /GRANT\sALL\sPRIVILEGES\sON\sjasmin_db\./ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string28 = /htdocs\/database\/jasmin_db\.sql/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string29 = /http.{0,1000}\/alertmsg\.zip/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string30 = /http\:\/\/127\.0\.0\.1\/handshake\.php/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string31 = /Jasmin\sDecryptor\.csproj/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string32 = /Jasmin\sDecryptor\.exe/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string33 = /Jasmin\sDecryptor\.pdb/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string34 = /Jasmin\sDecryptor\.sln/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string35 = /Jasmin\sEncryptor\.csproj/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string36 = /Jasmin\sEncryptor\.exe/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string37 = /Jasmin\sEncryptor\.sln/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string38 = /Jasmin\sEncryptor\\bin\\Release/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string39 = /Jasmin\sRansomware\sC2\sCheckin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string40 = /Jasmin\%20Decryptor\.exe/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string41 = /Jasmin\%20Decryptor\.pdb/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string42 = /Jasmin\%20Encryptor\.exe/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string43 = /Jasmin_Decryptor\.mainform/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string44 = /Jasmin_Decryptor\.Properties/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string45 = /\'jasminadmin\'\@\'localhost\'/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string46 = /jasmin\-ransomware\-master/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string47 = /The\sRansomware\sfor\sRedTeams\sCoded\sby\sSiddhant\sGour\swith\s/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string48 = /VXpCMk1UTjBjMU14YkhZemNsSTBibk13YlhjMGNqTQ/ nocase ascii wide

    condition:
        any of them
}
