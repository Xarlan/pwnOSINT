# pwnOSINT
Simple tool to aggregate data during pentest

At the first stage result stored in files in directory "output"

## Hot to use

```
$./osint.py [OPTIONS] COMMAND [ARGS]

```

**Support command**:

* **dns2ip**

```
Usage: osint.py dns2ip [OPTIONS] FIN

  Find ip address related with dns name

Options:
  -fout TEXT            Name of file to store result
  -humanr / -no-humanr  Store result for human read format
  -h, --help            Show this message and exit.
```
Where *'FIN'* is the file, contain list of DNS name


* **mdirb**
```
Usage: osint.py mdirb [OPTIONS] WEBURLS

  Run 'dirb' tools for multiply url

Options:
  -th INTEGER  Max thread for dirb
  -h, --help   Show this message and exit.
```
Where *'WEBURLS'* - file, contain list of 

* **sengine**
```
Usage: osint.py sengine [OPTIONS] FIN

  Get information from search engine. At this moment from Shodan

Options:
  -fout TEXT            Name of file to store result
  -api-key TEXT         API KEY fot Shodan
  -tout [ip|port|all]   Type of output
  -humanr / -no-humanr  Store result for human read format
  -h, --help            Show this message and exit.
```
Where *'FIN'* is the file, which contain list of ip-address to get information

* **tlscheck**

```
Usage: osint.py tlscheck [OPTIONS] FIN

  Check TLS/SSL server setting
  Fot this used sslyze library https://github.com/nabla-c0d3/sslyze:

Options:
  -p, --ports TEXT      Scan Ports
  -fout TEXT            Name of file to store result
  -th INTEGER           Max thread
  -humanr / -no-humanr  Store result for human read format
  -h, --help            Show this message and exit.
```
Where *'FIN'* is the file, which contain list of ip addrees to chekc TLS/SSL server settings

[SSLyze Documentation](https://nabla-c0d3.github.io/sslyze/documentation/)


* **urls**
```
Usage: osint.py urls [OPTIONS] FIN

  Check availability of web-interface/web-resource;
  very similar like 'curl -I http://some_site'

Options:
  -timeout INTEGER      How many second wait the answer
  -p, --ports TEXT      Scan Ports
  -fout TEXT            Name of file to store result
  -humanr / -no-humanr  Store result for human read format
  -h, --help            Show this message and exit.
```
Where *'FIN'* is the file, contain list of url-address

* **xml2txt**
```
Usage: osint.py xml2txt [OPTIONS] XML

  Convert xml file from 'masscan' tool to txt file, sorted by ip or by port

Options:
  -fout TEXT            Name of file to store result
  -tout [ip|port|all]   Sort by ip, port or both
  -humanr / -no-humanr  Store result for human read format
  -h, --help            Show this message and exit.
```
Where *'XML'* is the file, where store result of [masscan](https://github.com/robertdavidgraham/masscan) tool



## Installation and usage
* ```$git clone https://github.com/Xarlan/pwnOSINT.git```
* ```$cd pwnOSINT```
* ```$python3 -m venv /path/to/new/virtual/environment/venv```
* to activate virtual envinronment: ```. venv/bin/activate```
* it is recommended upgrade pip ```pip install --upgrade pip```
* ```$pip install -r requirements.txt```
* ```$./osint.py <some_command>```


### What mean '-humanr' option in command

Usually, result stored like:
```
ip:ip_v4_address => tcp/80
ip:ip_v4 address => tcp/443
ip:ip_v4 address => tcp/10000
ip:ip_v4 address => tcp/12345
```

It is easy to future analyze, use and etc...
*-humanr* flag allow you get additional file, where store information like this:
```
ip:ip_v4_address 
                 => tcp/80
                 => tcp/443
                 => tcp/10000
                 => tcp/12345
```

