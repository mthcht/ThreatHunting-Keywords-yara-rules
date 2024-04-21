rule cstealer
{
    meta:
        description = "Detection patterns for the tool 'cstealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cstealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: stealer discord token grabber, crypto wallet stealer, cookie stealer, password stealer, file stealer etc. app written in Python.
        // Reference: https://github.com/can-kat/cstealer
        $string1 = /\scstealer\.py/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string2 = /\sNiceRAT\.py/ nocase ascii wide
        // Description: stealer discord token grabber, crypto wallet stealer, cookie stealer, password stealer, file stealer etc. app written in Python.
        // Reference: https://github.com/can-kat/cstealer
        $string3 = /\/cstealer\.git/ nocase ascii wide
        // Description: stealer discord token grabber, crypto wallet stealer, cookie stealer, password stealer, file stealer etc. app written in Python.
        // Reference: https://github.com/can-kat/cstealer
        $string4 = /\/cstealer\.py/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string5 = /\/NiceRAT\.git/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string6 = /\/NiceRAT\.py/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string7 = /\/NiceRAT\-1\.0\.0\.zip/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string8 = /\/t\.me\/NicestRAT/ nocase ascii wide
        // Description: stealer discord token grabber, crypto wallet stealer, cookie stealer, password stealer, file stealer etc. app written in Python.
        // Reference: https://github.com/can-kat/cstealer
        $string9 = /\\cstealer\.py/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string10 = /\\NiceRAT\.py/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string11 = /\\NiceRAT\-1\.0\.0\.zip/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string12 = /\\NiceRAT\-main\\/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string13 = /0x00G\/NiceRAT/ nocase ascii wide
        // Description: stealer discord token grabber, crypto wallet stealer, cookie stealer, password stealer, file stealer etc. app written in Python.
        // Reference: https://github.com/can-kat/cstealer
        $string14 = /3ec41c041f4c5b1c1c781ddcd9d0286a0a920253783edb27a8fc8085d9ecb6f8/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string15 = /7f5ac429cd84d6ac935855b8a7656b830a6eefa1884f7fddd8c7c893c6b09ca4/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string16 = /aeachknmefphepccionboohckonoeemg/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string17 = /afbcbjpbpfadlkmhmclhkeeodmamcflc/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string18 = /agoakfejjabomempkjlepdflaleeobhb/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string19 = /aholpfdialjgjfhomihkjbmgjidlcdno/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string20 = /aiifbnbfobpmeekipheeijimdpnlpgpp/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string21 = /amkmjjmmflddogmhpjloimipbofnfjih/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string22 = /aodkkagnadcbobfpggfnjeongemjbjca/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string23 = /bfnaelmomeimhlpmgjnjophhpkkoljpa/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string24 = /bhghoamapcdpbohphigoooaddinpkbai/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string25 = /bhhhlbepdkbapadjdnnojkbgioiodbic/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string26 = /C4RD\sN4M3\:\s.{0,1000}\|\sNUMB3R\:/ nocase ascii wide
        // Description: stealer discord token grabber, crypto wallet stealer, cookie stealer, password stealer, file stealer etc. app written in Python.
        // Reference: https://github.com/can-kat/cstealer
        $string27 = /can\-kat\/cstealer/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string28 = /cgeeodpfagjceefieflmdfphplkenlfk/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string29 = /CH3CK70K3N\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string30 = /cjelfplplebdjjenllpjcblmjkfcffne/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string31 = /crcreditcards\.txt/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string32 = /CrealPasswords\.txt/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string33 = /crpasswords\.txt/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string34 = /CryptUnprotectData\(/ nocase ascii wide
        // Description: stealer discord token grabber, crypto wallet stealer, cookie stealer, password stealer, file stealer etc. app written in Python.
        // Reference: https://github.com/can-kat/cstealer
        $string35 = /CStealer\sBuilder\s\~\s/ nocase ascii wide
        // Description: stealer discord token grabber, crypto wallet stealer, cookie stealer, password stealer, file stealer etc. app written in Python.
        // Reference: https://github.com/can-kat/cstealer
        $string36 = /CStealer_assets\\/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string37 = /curl\s\-F\s.{0,1000}\shttps\:\/\/.{0,1000}\.gofile\.io\/uploadFile/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string38 = /D3CrYP7V41U3\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string39 = /db7d3e12a58a102b76c1f6e041d0a464ccbffc346dbc338a8cb4a7e5ec508b6c/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string40 = /dngmlblcodfobpdpecaadgfbcggfjfnm/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string41 = /ebfidpplhabeedpnhjnobghokpiioolj/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string42 = /efbglgofoippbgcjepnhiblaibcnclgk/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string43 = /egjidjbpglichdcondbcbdnbeeppgdph/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string44 = /eigblbgjknlfbajkfhopmcojidlgcehm/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string45 = /ejbalbakoplchlghecdalmeeeajnimhm/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string46 = /ejjladinnckdgjemekebdpeokbikhfci/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string47 = /ffnbelfdoeiohenkjibnmadjiehjhajb/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string48 = /fhbohimaelbohpjbbldcngcnapndodjp/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string49 = /fhilaheimglignddkjgofkcbgekhenbh/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string50 = /fnjhmkhhmkbjkkabndcnnogagogbneec/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string51 = /fnnegphlobjdpkhecapkijjdkgcjhkib/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string52 = /G374U70F111\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string53 = /G3770K3N\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string54 = /G3770K3N1NF0\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string55 = /G37800KM4rK5\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string56 = /G3781111N6\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string57 = /G3784D63\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string58 = /G378r0W53r5\(br0W53rP47H5\)/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string59 = /G37C00K13\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string60 = /G37C0D35\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string61 = /G37CC5\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string62 = /G37D15C0rD\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string63 = /G37D474\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string64 = /G37H1570rY\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string65 = /G37P455W\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string66 = /G37UHQ6U11D5\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string67 = /G37UHQFr13ND5\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string68 = /G37W3851735\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string69 = /G47H3rZ1P5\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string70 = /hmeobnfnfcmdkdcmlblgagmfpfboieaf/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string71 = /hnfanknocfeofbddgcijnmhnfnkdnaad/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string72 = /hpglfhgfnhbgpjdenjgmdgoeiappafln/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string73 = /https\:\/\/ptb\.discord\.com\/api\/webhooks\/1226217588959215726\/AZaNnD4TIN\-9sV\-t0rsveiQxcROYaCVziI8BUa6CNPsUxdnW9mdHu7HnuQ55kQPXZ8_5/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string74 = /ibnejdfjmmkpcnlpebklmnkoeoihofec/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string75 = /jblndlipeogpafnldhgmapagcccfchpi/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string76 = /K1W1F01D3r\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string77 = /K1W1F113\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string78 = /kncchdigobghenbbaddojjnnaogfppfj/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string79 = /kpfopkelmapcoipemfendmdcghnegimn/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string80 = /L04DUr118\(h00k/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string81 = /lgmpcpglpngdoalbgeoldeajfclnhafa/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string82 = /lpfcbjknijpeeillifnkikgncikgfhdo/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string83 = /mfgccjchihfkkindfppnaooecgfneiii/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string84 = /mgffkfbidihjpoaomajlbgchddlicgpn/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string85 = /nanjmdknhkinifnkgdcggcfnhdaammmj/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string86 = /NiceRAT\s\|\s.{0,1000}\s\sStealer/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string87 = /NiceRAT\-main\.zip/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string88 = /nkbihfbeogaeaoehlefnkodbefgpgknn/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string89 = /nkddgncdjgjfcddamfgcmfnlhccnimig/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string90 = /nlbmnnijcnlegkjjpcfjclmcfggfefdm/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string91 = /ojggmchlghnjlapmfbnjholfjkiidbch/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string92 = /ookjlbkiijinhpmnjffcofjonbfbgaoc/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string93 = /opcgpfmipidbgpenhmajoajpbobppdil/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string94 = /pdadjkfkgcafgbceimcpbkalnfnepbnk/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string95 = /phkbamefinggmakgklpkljjmgibohnba/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string96 = /r3F0rM47\(listt/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string97 = /S74r77Hr34D\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string98 = /s74r787Hr34D\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string99 = /SQ17H1N6\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string100 = /TrU57\(C00K13s\)/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string101 = /UP104D7060F113\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string102 = /UP104D70K3N\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string103 = /Wr173F0rF113\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string104 = /www\.nicerat\.com/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string105 = /Z1P73136r4M\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string106 = /Z1P7H1N65\(/ nocase ascii wide
        // Description: NiceRAT stealer - clone of cstealer
        // Reference: https://github.com/0x00G/NiceRAT
        $string107 = /Z1PF01D3r\(/ nocase ascii wide

    condition:
        any of them
}
