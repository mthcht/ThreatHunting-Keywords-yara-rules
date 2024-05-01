rule tunnelmole_client
{
    meta:
        description = "Detection patterns for the tool 'tunnelmole-client' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnelmole-client"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string1 = /\stunnelmole\.bundle\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string2 = /\.bin\/tmole/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string3 = /\.bin\/tunnelmole/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string4 = /\/bin\/tunnelmole\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string5 = /\/tunnelmole\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string6 = /\/tunnelmole\-client\.git/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string7 = /\/tunnelmole\-service/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string8 = /\/tunnelmole\-service\.git/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string9 = /\\\.tmole\.sh\\/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string10 = /\\tmole\.exe/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string11 = /\\tunnelmole\.bundle\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string12 = /25191b226ad7ef139f81890c531b0c606c5645bbca6f149b3679b06c73e6cddc/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string13 = /2b4328c30b58ecaf6febe1d7225b543b8886dcb4d8295be5973e6dc36f62c0f2/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string14 = /dashboard\.tunnelmole\.com/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string15 = /f38fg\.tunnelmole\.net/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string16 = /http\:\/\/.{0,1000}\.tunnelmole\.net/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string17 = /https\:\/\/.{0,1000}\.tunnelmole\.net/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string18 = /https\:\/\/tunnelmole\.com\/docs/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string19 = /https\:\/\/tunnelmole\.com\/downloads\/tmole\.exe/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string20 = /install\.tunnelmole\.com/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string21 = /node\stunnelmole\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string22 = /npm\sinstall\s\-g\stunnelmole/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string23 = /npm\sinstall.{0,1000}\stunnelmole/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string24 = /\-\-output\stmole\.exe/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string25 = /robbie\-cahill\/tunnelmole\-client/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string26 = /service\.tunnelmole\.com/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string27 = /tmole\s\-\sShare\syour\slocal\sserver\swith\sa\sPublic\sURL/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string28 = /tmole\s\-\-set\-api\-key\s/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string29 = /\'Tunnelmole\sService\slistening\son\shttp\sport\s/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string30 = /Tunnelmole\sService\slistening\son\swebsocket\sport\s/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string31 = /tunnelmole\/cjs/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string32 = /TUNNELMOLE_TELEMETRY/ nocase ascii wide

    condition:
        any of them
}
