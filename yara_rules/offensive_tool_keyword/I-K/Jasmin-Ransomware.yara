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
        $string2 = /\.500\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string3 = /\.docx\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string4 = /\.jpeg\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string5 = /\.jpg\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string6 = /\.pdf\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string7 = /\.png\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string8 = /\.pptx\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string9 = /\.txt\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string10 = /\.xlsx\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string11 = /\/jasmin\-ransomware\.git/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string12 = /\\Jasmin\sDecryptor\\/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string13 = /\\Jasmin\sDecryptor\\/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string14 = /\\Jasmin\sRansomware\sFinal\\/ nocase ascii wide
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
        $string20 = /\>Jasmin\sEncryptor\</ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string21 = /\>Jasmin\sRansomware\<\/div\>/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string22 = /6FF9974C\-B3C6\-4EEA\-8472\-22BE6BD6F5CD/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string23 = /78C76961\-8249\-4EFE\-9DE2\-B6EF15A187F7/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string24 = /ba41cc2f4c5dfb7df874b0e92f99f33b37b11574aab288d229749eba00e98813/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string25 = /C\:\\\\Users\\\\Public\\\\Windows\\\\Ui\\\\/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string26 = /C\:\\Users\\cyberstair\\/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string27 = /c062b58a1151df4a0ebad3d9246f69342b0ac1ecf5e5a5c4116f292994c481bd/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string28 = /c51005736c67304bf96c0e5421ce44f700578b87dbc912a820fd38dfa146fe41/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string29 = /codesiddhant\/jasmin\-ransomware/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string30 = /ConsoleHost_history\.txt\.jasmin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string31 = /CREATE\sDATABASE\sjasmin_db/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string32 = /d24cfba28aeecfecb7698350ca04c4ed07f6a9b88b212bbcbaacd168372fa980/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string33 = /GRANT\sALL\sPRIVILEGES\sON\sjasmin_db\./ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string34 = /handshake.{0,1000}jasmin\@123/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string35 = /htdocs\/database\/jasmin_db\.sql/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string36 = /http.{0,1000}\/alertmsg\.zip/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string37 = /http\:\/\/127\.0\.0\.1\/handshake\.php/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string38 = /https\:\/\/cnc\.mkbot\.info\/alertmsg\.zip/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string39 = /https\:\/\/cnc\.mkbot\.info\/handshake\.php/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string40 = /Jasmin\sDecryptor\.csproj/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string41 = /Jasmin\sDecryptor\.exe/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string42 = /Jasmin\sDecryptor\.pdb/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string43 = /Jasmin\sDecryptor\.sln/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string44 = /Jasmin\sEncryptor\.csproj/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string45 = /Jasmin\sEncryptor\.exe/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string46 = /Jasmin\sEncryptor\.sln/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string47 = /Jasmin\sEncryptor\\bin\\Release/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string48 = /Jasmin\sRansomware\sC2\sCheckin/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string49 = /Jasmin\%20Decryptor\.exe/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string50 = /Jasmin\%20Decryptor\.pdb/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string51 = /Jasmin\%20Encryptor\.exe/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string52 = /Jasmin_Decryptor\.mainform/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string53 = /Jasmin_Decryptor\.Properties/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string54 = /\'jasminadmin\'\@\'localhost\'/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string55 = /jasmin\-ransomware\-master/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string56 = /namespace\sJasmin_Encrypter/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string57 = /The\sRansomware\sfor\sRedTeams\sCoded\sby\sSiddhant\sGour\swith\s/ nocase ascii wide
        // Description: Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // Reference: https://github.com/codesiddhant/Jasmin-Ransomware
        $string58 = /VXpCMk1UTjBjMU14YkhZemNsSTBibk13YlhjMGNqTQ/ nocase ascii wide

    condition:
        any of them
}
