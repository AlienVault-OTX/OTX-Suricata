
# OTX Suricata Rule Generator
The OTX Suricata Rule Generator can be used to create the rules and configuration for Suricata to alert on indicators from your OTX account (otx.alienvault.com).  This is done with the suricata IP Reputation and file extraction features.  For every pulse your are subscribed to this will add the all the IPv4 indicators in every pulse to a generated IP reputation file.  It will also create a suricata MD5 file for each pulse that has MD5 indicators, there will be a corresponding rule generated that corresponds with each of these files.

## BETA NOTICE
This is under active development.  It has been tested in our lab in scenarios to replicate realworld installs.  However, Suricata is a complicated product with many configuration options.  If you have anything other than a default configuration, please adapt the output of this tool as appropriate.
As always feedback and improvements are welcome!

## Usage
1. Install OTX API (https://github.com/AlienVault-Labs/OTX-Python-SDK)
2. Run `python suricata.py` to see usage

>usage: suricata.py [-h] [--skip-iprep] [--skip-filemd5] [--key KEY]
>                   [--destination-directory DESTINATION_DIRECTORY]
>
>optional arguments:
>  -h, --help            show this help message and exit
>  --skip-iprep          Do not generate IP Reputation files and rules
>  --skip-filemd5        Do not generate file MD5 and rules
>  --key KEY             Your OTX API key (https://otx.alienvault.com/api)
>  --destination-directory DESTINATION_DIRECTORY, -dd DESTINATION_DIRECTORY
>                        The destination directory for the generated file
                        
3. Run `python suricata.py --key <OTX KEY>` to generate default IP Reputation and MD5 Rules
4. Follow instructions in output to integrate into your existing Suricata installation