---
layout: post
title: Identifying malicious TLS sessions
description: Logging and using TLS metadata to detect bad
categories: [ml, spl, zeek, nsm, network, security]
tags: [zeek,nsm,security,tls]
---

Inspired by an email from a former instructor, I created a [Zeek](https://zeek.org/) package, [spl-spt](https://github.com/micrictor/spl-spt), with the goal of providing new data that can be used to identify malicious TLS sessions. In this post, I will be discussing what the new data is, why I chose the data features I did, visualizing the data, and building a classification model using the data.


## Preface

The prevalence of data-in-transit encryption, most commonly done with Transport Layer Security (TLS) or Secure Sockets Layer (SSL), has severely limited the ability of monitoring tools to identify malicious network traffic. When used, TLS encrypts everything but the initial negotiation. Before TLS 1.3, this included the server's certificate, and optionally the Server Name Identifier (SNI), which could be used to identify the server being accessed by the client. Also included was information about what extentions and encryption algorithms the client and server supported, used by [ja3](https://github.com/salesforce/ja3) to generate a fingerprint of each side. TLS 1.3, however, includes the ability to send data before the handshake process when the client and server have previously communicated via [HTTP Early Data](https://tools.ietf.org/id/draft-thomson-http-replay-01.html#rfc.section.5), also known as [0-Round Trip Time (0-RTT)](https://blog.cloudflare.com/introducing-0-rtt/), which I suspect will see use as a method of avoiding network analysis.

*Encrypted SNI (ESNI) is not a mandatory part of TLS 1.3, nor is it widely supported, but it is currently included in Firefox Nightly and Brave. For more information, see https://blog.cloudflare.com/encrypted-sni/
 

## Table of Contents
[What data, anyway?](#what-data-anyway) 

[Visualizing the difference](#visualizing-the-difference) 

[Classification model](#classification-model) 

[Conclusion](#conclusion)

## What data, anyway?
As discussed in the [preface](#preface), new protocol standards will eliminate all of the metadata currently in use to profile encrypted network traffic. Since malicious actors also use TLS to protect their command and control channels, it is important that new analysis techniques are developed to account for this. While researching this problem, I came across [this post by Blake Anderson, a Cisco employee at the time.](https://blogs.cisco.com/security/detecting-encrypted-malware-traffic-without-decryption) In it, he explains how using tradional netflow data, such as session duration and number of packets per endpoint, is not enough. He goes on to show that by including data on the per-packet size and the interval between packets, a random-forest classifier can identify malware with a minimum of 30% fewer false negatives, and a maximum of a 1.5% increase in false positives, depending on the certainty threshhold.  
 
Inspired by Blake's post, I created a Zeek package, [spl-spt](https://github.com/micrictor/spl-spt), to generate the size and interval data for the TLS encrypted records. Note that while I named the package for packet lengths and times, technically it is recording the length of the TLS record, not the entire packet. By default, only the first twenty encrypted records will have their information logged in an effort to reduce the total size of the log, and simplify computations on the resulting vector. 
 
By intentionally not generating data for the TLS handshake performed before the encrypted stream begins, the amount of noise at the beginning of the vectors should be reduced. Since malicious agents [are advised to use widely avaiable server software](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki#https) to avoid detection, any data on the size or timing of the handshake is unlikely to be highly useful in the identification of malicious traffic. 

## Visualizing the difference 
In order to confirm my hypothesis that malicious traffic will exhibit a detectable difference in the newly collected data, I first simply graphed the values observed for both a collected PCAP of myself browsing Google, and a PCAP of the Shade ransomware. I did this inside of a Jupyter notebook running Python 3, using Pandas to load and manipulate the data and matplotlib to graph the data. To see the code behind the generation of the graphs I will be referencing, see [this Python script](https://github.com/micrictor/spl-spt/blob/master/samples/Visualization.py). 
 

First, I graphed the record lengths from the session source in both cases. 
 

![SPL-O]({{ site.baseurl }}/images/spl-o.png) 

Note that, even with the differences in scale on the y-axis, there is still a noticable difference between the two samples. In a normal web request, the first few requests may include larger records. This is most likely due to things like tracking cookies and authentication APIs which require a POST request with some data. In the malicious example, though, while there is a similar spike among the first few records, there is a far more notable pattern of increased record sizes later in the session. This will increase the average record size, and more specifically increase the average record size of the top percentiles.

Now, I graphed the same metric, record lengths, from the session destination. 

![SPL-R]({{ site.baseurl }}/images/spl-r.png) 

On average, the record lengths for the regular web traffic are _much_ smaller than the lengths for the malicious traffic. This is especially obvious for the first 20-30 records. The malicious server sends multiple records [of the maximum length allowed by the TLS standard, 16384 bytes](https://tools.ietf.org/html/rfc5246#section-6.2.1) right away, while the normal web browsing session sends no similarly large record, likely an indicator of the server transmitting a large file. 

Below are the graphs for the inter-record timings. 

![SPT-O]({{ site.baseurl }}/images/spt-o.png) 
![SPT-R]({{ site.baseurl }}/images/spt-r.png) 

 
 
While there is a striking spike in responder times for the malicious traffic later in the session, I'm unsure that this would be useful in a model aimed to identify malicious traffic. I believe that such timing information is likely to merely indicate that there is some high-latency process, such as a database query, occuring between records, or a random event like network congestion. For this reason, I will exclude it from my model. 

## Classification model
To explore the use of the new data in the identification of malicious network traffic, I built a decision-tree model in Python. Using Jupyter, Pandas, and Scikit-learn, I was able to build a model that acheived a miniumum of 86% accuracy at this task. If you would like to review the code, I have it hosted [on my GitHub](https://github.com/micrictor/spl-spt/tree/master/samples).

After loading all the data using Pandas, I first need to know how my data is split to ensure that my model is better than the null classifier.
```
Malicious sessions:	91
Benign sessions:	104
Malicious:			46%
Benign:				54%
```

So, in order to be better than the null classifier, or "just guessing", we need an overall accuracy higher than the highest density population, 54%.

Next, I created a series of new columns using _df.apply_ to create summary metrics of the record lengths per session.
```
def get_column_max(row, col):
    if col in row:
        if not isinstance(row[col],list):
            return row[col]
        return max(row[col])
    return 0
    
def get_column_min(row, col):
    if col in row:
        if not isinstance(row[col],list):
            return row[col]
        return max(row[col])
    return 0
    
def get_column_avg(row, col):
    if col in row:
        if not isinstance(row[col],list):
            return row[col]
        return sum(row[col]) / len(row[col])
    return 0

def get_column_range(row, col):
    if col in row:
        if not isinstance(row[col],list):
            return row[col]
        return max(row[col]) - min(row[col])
    return 0

def get_column_p_avg(row, col, l_p, t_p):
    if col in row:
        if not isinstance(row[col],list):
            return row[col]
        
        arr_size = len(row[col])
        # Sort a copy so we don't modify the array
        sort_arr = row[col].copy()
        sort_arr.sort()
        top_10pct_arr = sort_arr[int(arr_size * l_p):int(arr_size * t_p)]
        return sum(top_10pct_arr) / (1 if len(top_10pct_arr) == 0 else len(top_10pct_arr))
    return 0

df['max_orig_spl'] = df.apply(lambda row: get_column_max(row, 'orig_spl'), axis=1)
df['min_orig_spl'] = df.apply(lambda row: get_column_min(row, 'orig_spl'), axis=1)
df['avg_orig_spl'] = df.apply(lambda row: get_column_avg(row, 'orig_spl'), axis=1)
df['range_orig_spl'] = df.apply(lambda row: row.max_orig_spl - row.min_orig_spl, axis=1)
df['top_10p_avg_orig_spl'] = df.apply(lambda row: get_column_p_avg(row, 'orig_spl', 0.9, 1), axis=1)
df['bot_80p_avg_orig_spl'] = df.apply(lambda row: get_column_p_avg(row, 'orig_spl', 0, 0.8), axis=1)


df['max_resp_spl'] = df.apply(lambda row: get_column_max(row, 'resp_spl'), axis=1)
df['min_resp_spl'] = df.apply(lambda row: get_column_min(row, 'resp_spl'), axis=1)
df['avg_resp_spl'] = df.apply(lambda row: get_column_avg(row, 'resp_spl'), axis=1)
df['range_resp_spl'] = df.apply(lambda row: row.max_resp_spl - row.min_resp_spl, axis=1)
df['top_10p_avg_resp_spl'] = df.apply(lambda row: get_column_p_avg(row, 'resp_spl', 0.9, 1), axis=1)
df['bot_80p_avg_resp_spl'] = df.apply(lambda row: get_column_p_avg(row, 'resp_spl', 0, 0.8), axis=1)
```

Testing the performance of a decision tree model using subsets of these features, we get the following metrics:
```
Testing models over 1000 iterations...
Test data sample size: 59

Results with top 10 percentile average...
	Max accuracy :		1.0
	Min accuracy :		0.8135593220338984
	Max false negative:	0.11864406779661017	7
	Max false positive:	0.11864406779661017	7
Results with bot 80 percentile average...
	Max accuracy :		1.0
	Min accuracy :		0.8135593220338984
	Max false negative:	0.1016949152542373	6
	Max false positive:	0.1694915254237288	10
Results with just min/max/avg...
	Max accuracy :		1.0
	Min accuracy :		0.7966101694915254
	Max false negative:	0.13559322033898305	8
	Max false positive:	0.15254237288135594	9
Results with all features...
	Max accuracy :		1.0
	Min accuracy :		0.864406779661017
	Max false negative:	0.11864406779661017	7
	Max false positive:	0.11864406779661017	7
```

While all of the 100% accuracy results are likely a result of extreme overfitting due to the small sample size, it is very promising that even the worst performing model outperforms the null classifier by over 20%. 


## Conclusion
While I do not pretend to be an established data scientist, I think that my results show promise for using the data my package generates to detect malicious traffic. If you spot an issue in my methodology, or find additional ways to derive useful features from the data, feel free to create an issue or pull request on GitHub.

Given the continous move towards complete encryption of data-in-transit, analysis techniques based upon metadata will only grow in importance. As previously discussed, TLS 1.3 may provide significant obstacles to current analysis techniques. Similarly, there are already [proposed augmentations to IPSec](https://link.springer.com/chapter/10.1007/978-0-387-79026-8_22) that would render the analysis techniques described here obsolete, but I'm sure someone will develop a way to derive actionable insights with that as well.