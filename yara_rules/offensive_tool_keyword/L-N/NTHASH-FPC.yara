rule NTHASH_FPC
{
    meta:
        description = "Detection patterns for the tool 'NTHASH-FPC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTHASH-FPC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string1 = /\s\/changentlm.{0,1000}\s\/user\:.{0,1000}\s\/oldhash\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string2 = /\s\/changentlm.{0,1000}\s\/user\:.{0,1000}\s\/oldpwd\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string3 = /\s\/changentlm.{0,1000}\s\/user\:.{0,1000}\s\/oldpwd\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string4 = /\s\/decodemk\s\/binary\:.{0,1000}\s\/password\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string5 = /\s\/dumpsecret\s\/input\:.{0,1000}\s\/system/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string6 = /\s\/dumpsecret\s\/input\:defaultpassword/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string7 = /\s\/dumpsecret\s\/input\:dpapi_system\s\/offline/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string8 = /\s\/gethmac\s\/mode\:hashid\s\/input\:.{0,1000}\s\/key\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string9 = /\s\/getlsasecret\s\/input\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string10 = /\s\/getntlmhash\s\/password\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string11 = /\s\/getntlmhash\s\|\swtee\s.{0,1000}\.ntlm/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string12 = /\s\/getsamkey\s\/offline/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string13 = /\s\/ptt\s\/binary\:.{0,1000}\.kirbi/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string14 = /\s\/setntlm\s.{0,1000}\s\/user\:.{0,1000}\s\/newhash\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string15 = /\s\/setntlm\s.{0,1000}\s\/user\:.{0,1000}\s\/newpwd\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string16 = /\sby\serwan2212\@gmail\.com/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string17 = /\snc_srv\.bat/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string18 = /\srevshell32\.bin/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string19 = /\srevshell64\.bin/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string20 = /\.exe\s\s\/logonpasswords\s\/symbol/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string21 = /\.exe\s\/gethmac\s\/mode\:SHA1\s\/key\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string22 = /\/nc_srv\.bat/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string23 = /\/NTHASH\-FPC\.git/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string24 = /\/revshell32\.bin/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string25 = /\/revshell64\.bin/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string26 = /\\amsi\\dll\.zip/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string27 = /\\amsi\\hook\-win32\.dll/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string28 = /\\amsi\\hook\-win64\.dll/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string29 = /\\DumpSomeHashesAuto\.py/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string30 = /\\nc_srv\.bat/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string31 = /\\NTHASH\-FPC\\/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string32 = /\\revshell32\.bin/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string33 = /\\revshell64\.bin/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string34 = /\\wmiexec\.zip/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string35 = /_KIWI_BCRYPT_HANDLE_KEY/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string36 = /_KIWI_BCRYPT_KEY/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string37 = /_KIWI_BCRYPT_KEY81/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string38 = /_KIWI_MASTERKEY_CACHE_ENTRY/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string39 = /_NT6_CLEAR_SECRET/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string40 = /62f11b4ae2f0d26ed55efd4c918cfec1bd95036f507cf2dbf3295949831366ca/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string41 = /69ace7287faa4854605ab46018d92332ba0d16ff926ebf17330359a4dbd7d693/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string42 = /76c7648f79cc5a78f49e9ca24b26a82348e0292b3676ae04bdf22a88cb7eeadc/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string43 = /806ffe052652b8848d19fe26c63ecc35742077d87bbe04102b048a7c9c644c22/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string44 = /862f7ba58bbf77543812637ecc32d277fce062d21bc97587e5816e8fb05634e3/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string45 = /8bb972b4dc7e0c5b8db0be349ecf62043e69ea1273d5298f8e55c02fa047712c/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string46 = /91502e94bd83b8803e91d20d1b231c112d65561f588b92e888982f7753374e8d/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string47 = /bHNhc3MuZXhl/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string48 = /c\:\\temp\\nc\.exe/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string49 = /c96ef7d84ab7d43b03330daf4e78c11aa9407662f4a18d1824fa1506694c8c56/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string50 = /check\sthat\sour\sdll\sas\sbeen\sinjected\s\:\sNTHASH/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string51 = /e685904d607a73c1916b6a7d9cc2eb42e4afd1cf2e77e728b7dbeb141eda2735/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string52 = /erwan2212\/NTHASH\-FPC/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string53 = /Execute\(\'SELECT\sorigin_url\,username_value\,password_value\,length\(password_value/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string54 = /f56f11c598a47a0313a3f4e0929a45a6ed7529119189d7434fbe39721e190083/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string55 = /For\sfun\sand\s\(no\)\sprofit\s\:\slets\shook\srtlcomparememory\sin\slsass\.exe/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string56 = /go\sthru\seach\sline\sin\spasswords\.lst/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string57 = /hello\s\%3e\sc\:\\\\temp\\\\test\.txt/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string58 = /https\:\/\/erwan2212\.github\.io\/NTHASH\-FPC/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string59 = /https\:\/\/hashtoolkit\.com\/generate\-hash\/\?text\=/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string60 = /KIWI_KERBEROS_BUFFER/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string61 = /kuhl_m_dpapi_chrome\.c/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string62 = /kuhl_m_lsadump\.c/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string63 = /kuhl_m_sekurlsa_utils\.c/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string64 = /nc64\s127\.0\.0\.1\s9000\s\-e\scmd\.exe/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string65 = /nc64\s\-L\s\-vv\s\-p\s9000/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string66 = /NTHASH\s\/enumproc\s/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string67 = /NTHASH\s\/runas\s/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string68 = /NTHASH\s\/runaschild\s\/pid/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string69 = /NTHASH\s\/runastoken\s/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string70 = /NTHASH\s\/runwmi\s/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string71 = /NTHASH.{0,1000}\s\/cryptunprotectdata\s\/binary\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string72 = /NTHASH.{0,1000}\s\/cryptunprotectdata\s\/input\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string73 = /NTHASH.{0,1000}\s\/dumpsam/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string74 = /NTHASH.{0,1000}\s\/enumcred/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string75 = /NTHASH.{0,1000}\s\/enumvault/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string76 = /NTHASH.{0,1000}\s\/getlsakeys/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string77 = /NTHASH.{0,1000}\s\/wlansvc\s\/binary\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string78 = /NTHASH\-win32\.exe/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string79 = /NTHASH\-win64\.exe/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string80 = /offlinereg\-win32\.exe/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string81 = /offlinereg\-win64\.exe/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string82 = /reg\.exe\squery\shklm\\security\\policy\\secrets/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string83 = /rem\scall\snthash\-win64\s\/getntlmhash/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string84 = /rem\scheap\sbruteforce\s\.\.\.\svery\sslow\s\.\.\.\sok\sfor\sa\sfew\spasswords/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string85 = /THASH\s\/runts\s\/user\:/ nocase ascii wide
        // Description: various tools for retrieving windows secrets - Lateral Movement and C2
        // Reference: https://github.com/erwan2212/NTHASH-FPC
        $string86 = /toto\s\%3e\sc\:\\\\temp\\\\toto\.txt/ nocase ascii wide

    condition:
        any of them
}
