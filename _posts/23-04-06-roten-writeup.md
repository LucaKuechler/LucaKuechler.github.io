---
layout: post
title:  "Cyber Apocalypse 2023: Roten"
date:   2023-04-06 00:00:00
tags: [Wireshark, Apache, PHP]
description: 'Analyse HTTP requests in Wireshark and spot the Reverse Shell.'
categories: [WriteUp, Forensic, HTB-Cyber-Apocalypse-2023]
---

## Challenge Information
![Desktop View](/assets/img/roten-info.png){: .shadow }

First we start off by downloading the given zip archive. It contains one
network communication capture file: challenge.pcap. I decided to use Wireshark
to open the file, but you can do it from terminal too using tcpdump.

## Digging into challenge.pcap
As described in the scenario above, we can see a lot of HTTP requests that have
been made to our server. By looking at some HTTP packet headers, we find the
following information about the web server:
- domain: targetaggregator.intergalacticministry.com
- IP address: 172.31.9.156
- web server: Apache/2.4.52
- programming language: PHP

Because the description of the challenge mentioned a reverse shell that had
been uploaded, I started filtering for HTTP requests that had been interacting
with the target IP address.
```
http && ip.src==172.31.9.156
```
The output shows a ton of requests from the same IP address. If we add this as
the destination IP to the filter, we find out that 7265 requests are coming
from it. That looked very odd to me; nobody would send so many requests by
hand.
```
http && ip.src==172.31.9.156 && ip.dst==146.70.38.48
```
It looks like the attacker used a tool like Gobuster to scan the server's URLs,
looking for the file `galacticmap.php`. But it looked like all the URLs had not
been found.
```
hxxp://targetaggregator.intergalacticministry.com/{scanner-input}/galacticmap.php
```
So I decided to scan for requests that got answered with a different status
code than 404. Only 31 got a different answer. This looks like a number that
can be analyzed by a human. The new filter looked like this:
```
http && ip.src==172.31.9.156 && ip.dst==146.70.38.48 && http.response.code != 404
```
One URL accessed has the name
`hxxp://targetaggregator.intergalacticministry.com/uploads/galacticmap.php`. This
looks like the attacker finally found the file galactimap.php. A possible
misconfiguration can also be found. If you send a request to
`hxxp://targetaggregator.intergalacticministry.com/uploads/` it shows all the
files listed in the directory that were uploaded to the server. I removed the
filter and jumped to the previous request to search from there on. The attacker
found the file and tried a command line injection:
![packet-list](/assets/img/roten-packet-list.png)
![packet-info](/assets/img/roten-packet-info.png)
```
/uploads/galacticmap.php?dir=%2Fvar%2Fwww%2Fhtml%2Fuploads&cmd=whoami
-> www-data

/uploads/galacticmap.php?dir=%2Fvar%2Fwww%2Fhtml%2Fuploads&cmd=ls
-> asia-map.pdf
-> aus-map.pdf
-> galacticmap.php

/uploads/galacticmap.php?dir=%2Fvar%2Fwww%2Fhtml%2Fuploads&cmd=ls+%2F
-> bin boot dev etc home lib lib32 lib64 libx32 lost+found media 
   mnt opt proc root run sbin snap srv sys tmp usr var
```

## Find the reverse shell
But the question still remains: when and where has the reverse shell been
uploaded? For that, I asked myself how the hacker knew the filename
`galacticmap.php` he searched for. Maybe he uploaded it earlier. So there is a
good possibility that the file `galacticmap.php` is the reverse shell. So let's
try to search for that. It is most common to upload a file using a `POST`
request. So I tried filtering all the `POST` requests that have been made to the
server.
```
http.request.method == "POST"
```
![packet-list-post](/assets/img/roten-post-output.png)
One POST request rings my alarm bells because it states that the content type
is `application/x-php`. That is a common type for PHP reverse shells. If you
right-click on this request and select the option `Follow→HTTP stream`, you can
see the reverse shell.
![packet-reverse-shell](/assets/img/roten-reverse-shell.png)

## Extract the Flag
But we can’t see the flag and the code looks obfuscated. When looking at it,
you can see that it ends with the `eval($bhrTeZXazQ)` command, which means
everything inside the variable `$bhrTeZXazQ` is the code of the reverse shell. So
instead of executing it using eval, I tried printing it to the terminal using
echo. I started up a Docker container that can execute PHP files and replaces
eval with echo. Then I executed the PHP script and used grep to find the flag
inside the terminal output.
```bash
php script.php | grep HTB
```
