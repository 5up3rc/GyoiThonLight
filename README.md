# **GyoiThonLight**
**Next generation intelligence gatering tool**

---

### Presentation
 * [CSS2018](https://www.iwsec.org/ows/2018/)  

## Installation
#### Step.0 git clone GyoiThon's repository.
```
root@kali:~# git clone https://github.com/gyoisamurai/GyoiThonLight.git
```

#### Step.1 Get python3-pip
```
root@kali:~# apt-get install python3-pip
```

#### Step.2 install required packages.
```
root@kali:~# cd GyoiThonLight
root@kali:~/GyoiThonLight# pip3 install -r requirements.txt
```

#### Step.3 Edit config.ini of GyoiThonLight.
You have to be match server_host value with IP address of your Kali Linux.  

```
root@kali:~/GyoiThon# cd classifier4gyoithon
root@kali:~/GyoiThonLight# vim config.ini
```

## Usage
#### Step.0 Run GyoiThonLight
You execute GyoiThonLight following command.  

```
root@kali:~/GyoiThonLight# python3 gyoithon.py
```

#### Step.1 Check scan report
Please check scan report using any web browser.  

```
root@kali:~/GyoiThonLight# cd report
root@kali:~/GyoiThonLight/report# vim gyoithon_report_***.csv
```

## Operation check environment
 * Kali Linux 2018.2 (for Metasploit)
   * Memory: 8.0GB
   * Metasploit Framework 4.16.48-dev
 * ubuntu 16.04 LTS (Host OS)
   * CPU: Intel(R) Core(TM) i5-5200U 2.20GHz
   * Memory: 8.0GB
   * Python 3.6.1（Anaconda3）
   * docopt==0.6.2
   * pandas==0.23.4
   * google-api-python-client==1.7.4
   * Scrapy==1.5.1

## Licence
[Apache License 2.0](https://github.com/gyoisamurai/GyoiThonLight/blob/master/LICENSE)

## SNS
 * [Slack](https://gyoithon.slack.com)

## Contact us
 gyoiler3@gmail.com  

 * [Masafumi Masuya](https://www.blackhat.com/asia-18/arsenal/schedule/presenters.html#masafumi-masuya-36855)  
 [https://twitter.com/gyoizamurai](https://twitter.com/gyoizamurai)
 * [Isao Takaesu](https://www.blackhat.com/asia-18/arsenal/schedule/presenters.html#isao-takaesu-33544)  
 [https://twitter.com/bbr_bbq](https://twitter.com/bbr_bbq)

