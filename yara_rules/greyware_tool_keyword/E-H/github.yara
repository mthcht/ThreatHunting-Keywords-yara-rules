rule github
{
    meta:
        description = "Detection patterns for the tool 'github' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "github"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string1 = /.{0,1000}\/github\.com.{0,1000}\.exe\?raw\=true.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string2 = /.{0,1000}\/github\.com\/.{0,1000}\/archive\/refs\/tags\/.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string3 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.7z.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string4 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.apk.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string5 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.app.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string6 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.as.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string7 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.asc.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string8 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.asp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string9 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bash.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string10 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bat.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string11 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.beacon.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string12 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string13 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bpl.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string14 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.c.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string15 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cer.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string16 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cmd.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string17 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.com.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string18 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cpp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string19 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.crt.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string20 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string21 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.csh.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string22 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dat.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string23 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string24 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.docm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string25 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dos.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string26 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string27 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string28 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.gz.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string29 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.hta.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string30 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.iso.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string31 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.jar.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string32 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string33 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.lnk.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string34 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string35 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.mac.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string36 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.mam.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string37 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.msi.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string38 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.msp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string39 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.nexe.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string40 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.nim.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string41 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.otm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string42 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.out.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string43 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ova.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string44 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pem.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string45 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pfx.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string46 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pl.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string47 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.plx.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string48 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string49 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ppk.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string50 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string51 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.psm1.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string52 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pub.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string53 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string54 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pyc.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string55 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pyo.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string56 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.rar.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string57 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.raw.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string58 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.reg.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string59 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.rgs.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string60 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.RGS.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string61 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.run.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string62 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.scpt.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string63 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.script.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string64 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sct.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string65 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sh.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string66 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ssh.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string67 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sys.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string68 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.teamserver.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string69 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.temp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string70 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.tgz.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string71 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.tmp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string72 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vb.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string73 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vbs.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string74 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vbscript.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string75 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ws.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string76 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.wsf.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string77 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.wsh.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string78 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.X86.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string79 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.X86_64.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string80 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlam.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string81 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string82 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlsm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string83 = /.{0,1000}\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string84 = /.{0,1000}codeload\.github\.com\/.{0,1000}/ nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string85 = /.{0,1000}objects\.githubusercontent\.com\/github\-production\-release\-asset\-.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string86 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.7z.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string87 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.apk.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string88 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.app.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string89 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.as.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string90 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.asc.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string91 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.asp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string92 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.bash.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string93 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.bat.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string94 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.beacon.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string95 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string96 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.bpl.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string97 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.c.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string98 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.cer.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string99 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.cmd.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string100 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.com.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string101 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.cpp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string102 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.crt.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string103 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string104 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.csh.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string105 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.dat.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string106 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string107 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.docm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string108 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.dos.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string109 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string110 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string111 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.gz.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string112 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.hta.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string113 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.iso.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string114 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.jar.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string115 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string116 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.lnk.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string117 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string118 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.mac.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string119 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.mam.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string120 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.msi.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string121 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.msp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string122 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.nexe.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string123 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.nim.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string124 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.otm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string125 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.out.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string126 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.ova.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string127 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.pem.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string128 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.pfx.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string129 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.pl.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string130 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.plx.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string131 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.pm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string132 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.ppk.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string133 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string134 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.psm1.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string135 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.pub.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string136 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string137 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.pyc.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string138 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.pyo.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string139 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.rar.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string140 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.raw.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string141 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.reg.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string142 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.rgs.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string143 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.RGS.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string144 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.run.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string145 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.scpt.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string146 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.script.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string147 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.sct.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string148 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.sh.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string149 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.ssh.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string150 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.sys.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string151 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.teamserver.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string152 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.temp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string153 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.tgz.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string154 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.tmp.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string155 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.vb.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string156 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.vbs.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string157 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.vbscript.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string158 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.ws.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string159 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.wsf.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string160 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.wsh.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string161 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.X86.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string162 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.X86_64.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string163 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.xlam.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string164 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.xlm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string165 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.xlsm.{0,1000}/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string166 = /.{0,1000}raw\.githubusercontent\.com.{0,1000}\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
