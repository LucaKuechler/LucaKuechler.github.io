---
layout: post
title:  "Monitor Proxmox Firewall using Graylog"
date:   2022-10-07 00:00:00
tags: [Graylog, Proxmox, Filebeat, Grok]
description: ''
categories: [Documentation, SIEM, Firewall]
---

## Project Overview
As a cybersecurity enthusiast, I decided to create my own homelab last year.
There i can test different blue team tools and techniques. One of the main
challenges I faced was how to collect and analyze logs from different sources
within my homelab. After testing different SIEM options, I decided to stick to
Graylog due to its modern UI and built-in features. My homelab consists of an
old PC running Proxmox with several virtual machines (VMs) that are connected
via a virtual private network. As for the firewall, I stick to the Proxmox
built-in firewall. Unfortunately, there was no easy way to export its logs to
Graylog. To address this issue, I decided to use Filebeat and Graylog Sidecars
to collect and send firewall logs to Graylog. Here's a step-by-step guide on
how I did it.

## Setup
You will need a Proxmox instance which powers a virtual machine running
Graylog. Make sure that both the Proxmox and Graylog are able to communicate
with each other, otherwise the following steps will not work.

## Sidecars and Filebeat
![sidecars and filebeat architecture](/assets/img/proxmox-firewall-graylog.png)
_https://go2docs.graylog.org/5-0/getting_in_log_data/graylog_sidecar.html_

Graylog Sidecars are lightweight agents that can be used to manage log
collectors and data forwarding. They are designed to work with various types of
log collectors, including Filebeat. Filebeat is a lightweight data shipper,
which can be used to collect, parse, and forward log data to a centralized log
management system like Graylog. The Sidecar manages the API connection for
Filebeat, and is responsible for configuring and starting the Filebeat service.

## Configure Proxmox Firewall
I decided to only log requests that target my Proxmox instance. Otherwise it
would be to much data to store on my little server. For that you have to
activate firewall first, because it is turned off by default. To activate the
Proxmox firewall for the datacenter, follow these steps:

1. Log in to the Proxmox VE web interface.
2. Click on the "Datacenter" item in the left-hand menu.
3. Click on the "Firewall" tab.
4. Add the following rule to prevent loosing access to your web interface.
    
    ![Proxmox add rule ui](/assets/img/proxmox-firewall-add-rule.png)
    
5. Select the submenu options right next to the “Firewall” tab.
6. Check the "Enable firewall" checkbox.
7. Click on the "OK" button to save your changes.

Create a shell connection the your pve using the Proxmox VE web interface. If
everything worked the file `/var/log/pve-firewall.log` should exists and contain
some firewall requests. For more informations about the Proxmox firewall check
out the amazing tutorial from [Learn Linux TV](https://www.youtube.com/watch?v=DNsLLrCgK0U).

## Generate a Graylog API token
The API token is required for the Sidecars to authenticate with the graylog instance. If you do not already have one, you can generate one like this:
1. Visit http://&lt;graylog-hostname&gt;/system/sidecars.
2. Click on the link `Create or reuse a token for the graylog-sidecar user` which will redirect you to the token creation page.
3. Enter a custom token name and create it. In the following tutorial, I used the name filebeat.
4. Copy your generated token from the following output and save it somewhere. You will not be able to see it again.
  
    ![token output](/assets/img/proxmox-firewall-graylog-token.png)

## Install the Graylog Sidecar
As mentioned before the Sidecar manages the API connection for Filebeat. To
install both components, connect to your Proxmox instance. Remember, we
activated the firewall, so if SSH does not work, the web terminal will.
1. Install the Graylog Sidecar
    
    ```bash
    wget https://packages.graylog2.org/repo/packages/graylog-sidecar-repository_1-5_all.deb
    sudo dpkg -i graylog-sidecar-repository_1-5_all.deb
    sudo apt-get update && sudo apt-get install graylog-sidecar
    ```

2. Change the following lines inside the Sidecar configuration file

    ```
    # The URL to the Graylog server API.
    server_url: "http://<ip>:9000/api/"

    # The API token to use to authenticate against the Graylog server API.
    # This field is mandatory
    server_api_token: "<token>"
    ```
    {: file="/etc/graylog/sidecar/sidecar.yml"}

3. Generate the systemd service.
    
    ```bash
    sudo graylog-sidecar -service install
    sudo systemctl enable graylog-sidecar
    sudo systemctl start graylog-sidecar
    ```

4. If everything has worked the sidecar should appear here:
    
    ![sidecar overview](/assets/img/proxmox-firewall-sidecar-overview.png)

## Installing Filebeat
> Filebeat must also be installed on the Proxmox instance.
{: .prompt-info }

1. Download .deb file from the Filebeat [homepage](https://www.elastic.co/downloads/beats/filebeat).
    
    ```bash
    wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.6.2-amd64.deb
    ```

2. Install Filebeat on the system.
    
    ```bash
    sudo dpkg -i filebeat-8.6.2-amd64.deb
    ```

## Tell Graylog to listen for Filebeat data
> Defining the input after starting the Filebeat instance would result in a lot of connection errors.
{: .prompt-info }

Graylog Inputs serve as the entry point for collecting and processing log data
from various sources. It offers a wide range of input types, each designed
to handle different log formats and protocols. In our case we need to choose `Beat` as the input type.
1. Visit http://&lt;graylog-hostname&gt;/system/inputs.
2. Create a new input.
    ![graylog add input beat](/assets/img/proxmox-firewall-graylog-input-add.png)
3. Create new input confguration.
    ![graylog edit beat config](/assets/img/proxmox-firewall-graylog-input-edit.png)

## Configure Filebeat using the Graylog Interface
1. Visit http://&lt;graylog-hostname&gt;/system/sidecars.
2. Click on `Manage sidecar` as shown in the image below.
    ![graylog manage sidecar](/assets/img/proxmox-firewall-sidecar-manage.png)
3. Select `filebeat` in the list and click `Assign Configurations`.
    ![graylog manage sidecar](/assets/img/proxmox-firewall-sidecar-assign.png)
4. Choose `Add a new configuration`.
5. Now choose a name for your configuration. I decided to stick to the name
   `Linux-Proxmox-Firewall`. Your configuration should look something like
   this:
    ![graylog manage sidecar](/assets/img/proxmox-firewall-sidecar-config.png)
6. Copy the following yaml code inside the configuration text field. Don't forget to change the `proxmox-server-ip`.

    ```yaml
    # Needed for Graylog
    fields_under_root: true
    fields.collector_node_id: ${sidecar.nodeName}
    fields.gl2_source_collector: ${sidecar.nodeId}

    filebeat.inputs:
    - input_type: log
      paths:
        - /var/log/pve-firewall.log
      type: log
    output.logstash:
       hosts: ["<proxmox-server-ip>:5045"]
    path:
      data: ${sidecar.spoolDir!"/var/lib/graylog-sidecar/collectors/filebeat"}/data
      logs: ${sidecar.spoolDir!"/var/lib/graylog-sidecar/collectors/filebeat"}/log
    ```
7. Press `Update configuration` to save and exit. The Filebeat service should
   be started automatically. If this is not the case you can check it using
   `systemctl`.


## Conclusion
The Proxmox firewall logs should now appear under the search tab. The logs are
not divided into valid fields to search through. All the firewall log data is
parsed within the message attribute. To divide these further Graylog piplines
are needed. This will be covered in a future blog post.
