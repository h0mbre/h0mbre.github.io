---
layout: single
title: From Sec+ to OSCE: Lessons Learned 
date: 2019-8-03
classes: wide
header:
  teaser: /assets/images/CTP/immunity.jpg
tags:
  - Security+
  - Network+
  - CompTIA
  - Certified Ethical Hacker
  - EC Council
  - eCPPT
  - eWPT
  - eLearnSecurity
  - OSCP
  - OSCE
  - Offensive Security
  - Python
--- 
![](/assets/images/CTP/1920x1080_Wallpaper.jpg)

## Background Information
In late 2017 I decided I needed to shake things up and try to learn some new skills. I don't remember exactly how it happened but at some point I came across a job post for a 'Security Engineer' position and found the requirements to be very interesting. I started researching the skills mentioned, namely 'pentesting' and the related certifications. After digging more into penetration testing, I resolved to get OSCP within 18 months starting in January 2018. I'm going to describe how that endeavor ended up playing out, some strategies I found useful, the mistakes I feel like I made, and in the end whether or not it was worth the effort. The goal of this post is to potentially inspire someone to pursue any type of education or self-improvement while also potentially saving those interested in information security some time and optimizing their education path. 

At the time, I was working primarily as a Technical Writer which often lacks the sense of freedom associated with other types of writing. So while I was nominally touching/researching/writing about technical subjects, it's fair to say that I was not actually learning anything, much less retaining learned information. When I started this journey, I knew what a firewall was (solely because of Xbox Live) at a high-level but had no idea how they worked. I couldn't write a single line of code in any language. The entirety of my information security knowledge came from War Games, Hackers, and Mr. Robot. I actually randomly got my Net+ certification in 2015 hoping it would spark some new sense of purpose but unfortunately, I found the material mind-numbingly boring at the time and brain dumped 99% of the information within months after the bootcamp and certification test. As fate would have it, the way I chose to prepare for Security+ required me to also take a Network+ prep-class concurrently so I ended up relearning all of the material from scratch. I was by no means an IT professional when I started this journey. I knew nothing. I still know nothing. 

**Just a tiny disclaimer before we get started: I am by no means an expert at anything, in some ways I feel even more ignorant than when I started. I'm actually unqualified to do almost anything infosec. There is a ton I don't know. Do not take this blog post as gospel, this is simply my opinion and honestly, there's a good chance I'm wrong about a lot of it. Seek out other opinions in addition to those expressed within this blog post!**

In this post we will be dealing with the following certifications and learning exercises:
+ Sec+,
+ Net+,
+ Intro to Python,
+ CEH,
+ eCPPT,
+ OSCP,
+ eWPT,
+ SLAE x86, and
+ OSCE. 

## Security+ from CompTIA (January 2018 - June 2018)
According to [CompTIA](https://certification.comptia.org/certifications/security), Security+ is an entry-level security certification which 'establishes the core knowledge required of any cybersecurity role and provides a springboard into intermediate-level cybersecurity jobs.' I don't honestly take much issue with that description. The only thing that gives me pause is asserting Security+'s close proximity to intermediate positions. On its own, I don't believe it even prepares you for a single entry-level role, so to say it is a spring-board into intermediate roles might be a bit of a stretch. It's a springboard into intermediate roles the same way that 7th grade English class is a spring board into an English PhD program, you learn parts of speech and how to write papers; however, you're not exactly ready to defend a thesis afterwards. I won't go into insane detail about the contents of the course since that information is available all over the Internet; however, I will give my take on what I found useful about the class and also what I disliked. 

To prepare for the certification, I enrolled at a local community college and took a Security+ prep class which was offered as an elective for technical degree plans such as Computer Science, Computer Engineering, Cybersecurity, etc. The community college required that students enrolling in the Security+ class also enroll in a Network+ class. I had already achieved by Network+ certification in 2015, but since I had brain dumped virtually all of the information, I thought 'what the hell' and enrolled in that as well. The course I attended required us to maintain regular attendance which ended up being a nuisance. The professor was unqualified to teach a cybersecurity class to say the least and I spent the entirety of every class reading a [Security+ prep book by Darril Gibson](http://getcertifiedgetahead.com/index.php/security/) instead of listening to the lecture. Obviously this may not be the case if you choose to enroll in a prep-class offering. In fact, I hope it's not! When I was preparing for the certification, I found that reading Gibson's book cover to cover twice and then honing in on weak areas which were revealed via regular practice tests was more than enough to prepare me for the exam. I also listened to all of the [Security+ Professor Messer](https://www.professormesser.com/security-plus/sy0-501/sy0-501-training-course/) videos during my commutes to and from work for the 5 or 6 months I spent studying. The strategy of enrolling in a community college class to help me with prep ended up being a colossal mistake. I could've easily spent only 8 weeks self-studying and passed the exam; instead, I spent 5 months trekking to and from school with a Wife and Kids at home during week nights to ignore someone's lecture and work on my own. This will be a recurring theme in this blogpost but, trust your ability to self-study. If that ability is in fact non-existent, then yes, definitely seek out some hand-holding early on but teach yourself how to learn. Self-study is crucial in this field. 

Overall, I found the certification and the material covered to be fine! It's not meant to make you an expert obviously, and the material includes a ton of information but not much depth. This is to be expected for an entry-level certification. If you plan on working for the Department of Defense, the certification is also DoD 8570 compliant which is a nice plus and can help you get past some HR filters.

PROS: 
+ DoD 8570 Compliant;
+ Foundational knowledge for a wide variety of domains;
+ Geared towards complete beginners in security;
+ HR Filter friendly;
+ Robust free materials to self-study.

CONS: 
+ Expensive formal training;
+ Overwhelming amount of information that you will likely not use immediately, potentially leading to the dreaded braindump!
+ Not specialized for anyone seeking more in-depth information. 

I [once mentioned on Twitter](https://twitter.com/h0mbre_/status/1109834208283901952?s=20) that I had completed the certification and contrasted my feelings about it with my feelings about more practical certifications and received this response from @rotate26chars:
"...another way to view the CompTIA stuff is foundational. Though not hands-on, you will regularly fall back on the broader concepts you learn in your career.  IMHO they add a ton of context to the practical skills learned studying for hands-on certs. When I'm hiring someone with Net+/Sec+ certs, I'm not looking for someone whose able to tune a SIEM, or manage a firewall, I'm looking for someone who can learn how to do those things faster, and with a better understanding of how they fit into a broader security strategy." 

So straight from the mouth of someone who makes hiring decisions in the cybersecurity field, the certification shows that the holder at least has a foundational grasp of several knowledge domains and can more easily contextualize more esoteric concepts once hired. 

### Final Verdict
At first I think I had conflicting goals, I wanted hardcore technical skills but also wanted the ability to get my foot in the door in an information security role so I had to get at least some official bona fides onto my resume. This certification was good for the latter goal and also did at least impart upon me some lasting high-level understanding of security concepts. I found the lessons on the interplay between business decisions and risk management to be the most instructive.

All in all, I'd say if you're coming into information security with zero background knowledge, and especially if you need an 8570 certification, then it would be ok to take the course and aim for the certification. It's best suited for someone who cannot self-orient their desired learning path and doesn't know exactly what they don't know. This is where the broadness and lack of depth is actually a plus. You get introduced to so many different topics, maybe one will stoke your interest and you can specialize from there. My only suggestion would be that you self-study very hard for 8-12 weeks and not pursue any formal training. You can do this. 

If you're just after some skills/knowledge (especially practical skills on the keyboard), I would recommend taking a more targeted approach and again opting for self-study. If you want to study encryption, check out books and blog posts about encryption. If you want to study SIEM implementations and logging best practices for enterprise networks, again, look at some of the amazing blue-team blog posts that are out there. Obviously general security knowledge is great to have and can help you contextualize more advanced information; however, if you take a targeted approach and research things that come up as you progress in your narrow focus, you can often acheive a comparable level of background knowledge and often it'll be related in some way to your main interest (read 'useful'). 

## Network+ from CompTIA (January 2018 - June 2018)
According to [CompTIA](https://certification.comptia.org/certifications/network#overview), Network+ holders have the knowledge and skills to do the following:
+ Design and implement functional networks
+ Configure, manage, and maintain essential network devices
+ Use devices such as switches and routers to segment network traffic and create resilient networks
+ Identify benefits and drawbacks of existing network configurations
+ Implement network security, standards, and protocols
+ Troubleshoot network problems
+ Support the creation of virtualized networks.

To be brutally honest with you, I've actually taken a Network+ prep course twice and passed the certification exam and even given all of the supplemental learning I have done since, I would not feel comfortable doing a single one of these things in a professional capacity. I think this description is an exaggeration. We must also consider that I didn't immediately assume a junior networking role after taking the course, so the knowledge imparted by the certification was not immediately put to use. This could account for at least some of the lack of confidence I have in the description. Perhaps had I been thrust immediately into a networking role I would be saying the opposite, that the certification provided me with all of the foundational knowledge I needed to hit the ground running at my new job. We will never know because I brain dumped 95% of the information and to this day I don't know much about networking. Sad! 

As previously mentioned, I enrolled in a prep class at a local community college since it was required that I attend concurrently with my Security+ prep class. The professor teaching this course was actually great and a 'net plus' (hehe) on my learning experience. I actually found this course to be more technical than Security+, and as a result, more difficult. In the CompTIA hierarchy of certifications, Net+ comes before Sec+. A cool hack you can do is once you get a CompTIA certification, you can automatically renew it by taking a course/getting a certification that is hierarchically higher than your obtained certification. So, if you have a Level-1 certification and your 3-year window of renewal is closing, take and pass a Level-2 certification and the Tier-1 certification will be renewed for another 3 years. Eventually, you will have all the certs. 

In addition to the time in class, I went through the [Darril Gibson](http://getcertifiedgetahead.com/index.php/network/) book, and again, listened to the [Professor Messer](https://www.professormesser.com/network-plus/n10-007/n10-007-training-course/) videos during my commutes. Given that I didn't have a certification test looming at the end of the course (since I had obtained it in 2015), there was less pressure to learn the material. However, I still had my grade point average to consider and exams. I studied hard and did all of the extra credit in class, but sadly, I didn't retain much of the information since I did not use it immediately. I couldn't tell you off the top of my head the standards associated with IEE 802.11n. The one thing that did stick with me, and I'm not sure I'm physically capable of forgetting, is subnetting. You do so much subnetting in a Network+ prep class that it's impossible to forget. A bonus of the course was that it was hosted on a learning platform called Test Out which actually came with virtual labs to complete. The labs simulated configuring hardware, changing settings, troubleshooting network connectivity issues, etc. It wasn't exactly hands-on in a traditional sense but it was more useful than reading about the concepts in a purely abstract manner. 

The course is pretty close to Security+ in its overall structure; a brief introduction to a plethora of networking concepts.

PROS:
+ DoD 8570 Compliant;
+ Foundational knowledge for a wide variety of domains;
+ Geared towards complete beginners in security;
+ HR Filter friendly;
+ Robust free materials to self-study.

CONS:
+ Expensive formal training;
+ Overwhelming amount of information that you will likely not use immediately, potentially leading to the dreaded braindump!
+ Not specialized for anyone seeking more in-depth information;
+ Better training opportunities available for same domains of knowledge. 

### Final Verdict
I'm having a hard time recommending this certification for a couple of reasons. One, if you are curious about networking and want to explore it, I think self-study would more than suffice for that purpose. Through self-study, I think you will be able to determine whether or not the material and subject matter is captivating for you. Two, if you know for a fact you want to learn networking, I think there are better training alternatives which cover the material in more depth and actually will impart upon you the practical skills to at least perform *some* professional networking tasks with appropriate adult-level supervision. The Cisco certifications come to mind (at least the entry-level-ish ones like CCNA R&S). Three, if you think you need this certification on your resume to get your past an HR filter or get your foot in the door, that is a completely valid concern; however, the issue arises whenever we consider that the Cisco certifications better prepare you for professional networking roles and would also accomplish this same HR filter defeating goal. As an added bonus, any hiring manager who prefers Net+ over something like CCNA R&S just removed themselves from your list of potential employers! One less thing to worry about! 

But! If you're dead set on the certification then by all means go for it! It is 8570 compliant. It does provide some good foundational networking information for those who perhaps need networking knowledge but nothing too esoteric. Not everyone needs to be a networking guru, this is where this certification comes in. I think for the purposes of entry level pentesting, the kind of material covered in the certification course might be pretty spot on (again, I’m just guessing here I have no idea.) I just think if your goal is the information you need to do entry-level pentesting then you can do it without the certification. 

If you need an 8570 compliant certification for your resume then go for it! 

## Intro to Python (January 2018 - June 2018)
During the same semester that I took the Net+ and Sec+ classes at my community college, I also enrolled in an Intro to Python class and it was by far the best experience of this time period. The class structure was something you could *easily* recreate at home on your own without the need to enroll in a college course. We simply all purchased a copy of [Tony Gaddis' "Starting Out With Python"](https://www.amazon.com/Starting-Out-Python-Tony-Gaddis/dp/0134444329) and worked through a chapter a week basically. I loved this course and I found that everything I learned I would be using constantly as I started to take more and more pentesting centric courses and trainings. 

I wouldn't recommend taking a formal class for this level of programming honestly, I think it's more than doable at home on your own. Buy a used textbook and work through it. I also supplemented the course with the free Codeacademy Python course at the time, which was awesome. By the end of the book, I was writing Object Oriented programs that became pretty robust and complex. At the time, I thought I had put in a lot of hard work and time to learn everything but looking back it was probably only 8 hours a week or so that I spent studying. I didn't continue writing Python immediately after the class so a lot of the more complex concepts like the object oriented programming did not make it into the skillset I retained (did not braindump); however, the 70% or so knowledge that I did retain has come in very handy. 

Taking a formal college class ended up not adding much value over self-study. The course was offered online and the instructor didn't reply to questions in a timely manner, so I was basically on my own for the semester. 

### Final Verdict
Learn Python! Any intro to Python course/materials you can get your hands on will suffice. Being able to script things up, automate processes, and learning enough of one language to read and understand other languages/exploit code is very valuable. 

I don't know if Python is the first language you should learn to be honest, I just know it's relatively easy compared to others and I found that attractive (easy + powerful) as a beginner. I know some have argued to start with C as your first language since it will give you a better understanding of how programs/memory actually function, but I will leave that to the experts to comment on. I had a blast learning Python first and it enabled me to create a bunch of hacky tools that helped me out during my journey thus far. 

## Certified Ethical Hacker (July 2018) 
According to [EC Council](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/), the purpose of the CEH credential is to: 
+ Establish and govern minimum standards for credentialing professional information security specialists in ethical hacking measures.
+ Inform the public that credentialed individuals meet or exceed the minimum standards.
+ Reinforce ethical hacking as a unique and self-regulating profession.

I don't think the certification actually does any of those things unfortunately. To prepare for this course, my employer paid for me to attend a week long boot-camp and take the certification test on the last day. The certification test didn't closely align to the course material and a significant number of the exam questions felt like they were Google translated into English. Very frustrating to say the least.

This was my first foray into pentesting training. All of the relevant information in the materials is also included in more hands-on practical entry level penetration testing certifications like eCPPT from eLearnSecurity and OSCP from OffensiveSecurity. Not only do those practical courses contain the same relevant information, they also explain the concepts better and offer better supplemental resources (especially eCPPT). 

PROS:
+ DoD 8570 Compliant;

CONS:
+ Everything else!

### Final Verdict
I would say stay away from this certification unless you absolutely need it on your resume. I can't think of a single redeeming quality to this course or certification. It has been over a year at this point since I took this certification so maybe it has changed in the mean time, seek out some other opinions before making a decision. 

## eLearnSecurity Certified Professional Penetration Tester (eCPPTv2) (August 2018 - November 2018)
According to [eLearnSecurity](https://www.elearnsecurity.com/certification/ecppt/), an eCPPT holder is knowledgeable in the following domains:
+ Penetration testing processes and methodologies;
+ Vulnerability Assessment of Networks;
+ Vulnerability Assement of Web Applications;
+ Advanced Exploitation with Metasploit;
+ Pivoting;
+ Web application manual exploitation;
+ Information gathering and reconnaissance;
+ Scanning;
+ Privilege escalation and persistence;
+ Exploit Development; and
+ Advanced reporting skills and remediation. 

I can't really find anything to take issue with there. This course was it for me, this is what got me hooked. This course will make you a very capable Metasploit user and will also ensure your pivoting game is strong. 

This course was an absolute blast. This was my first exposure to actual hands-on penetration testing techniques. To give you an idea of where I was at when I started, on the first day of the course I spent about 3 hours trying to figure out how to install Openvpn on Kali Linux so that I could connect to the lab environment. (Spoiler alert: Openvpn is included with Kali Linux). I never wrote a standalone review of this course so I will try to do a light version here. 

To begin, I purchased PTPv5 with 120 hours of lab time. I ended up using ~100 hours of lab time preparing for the exam and I never even touched Linux or Web Application labs (my only caveat here is that I was probably biting off more than I could chew by jumping into this course as my first foray into hands-on training and that could explain the usage of lab time). My only qualm with the course was that the very first module they teach is 'System Security' which is the x86 stack buffer overflow chapter that attempts to teach the student about registers, assembly, shellcode, the stack, etc. It's quite technical for someone who doesn't know much ;). 

The way the course is set up is that it teaches you a concept via slides and then reinforces that concept with a video of an instructor demonstrating the concept. I found this method of teaching to be pretty instructive and was able to learn a lot this way. Lastly, you are presented with a lab scenario where you have to complete tasks related to the material you were just taught. I will give a word of warning here that sometimes the lab scenarios include knowledge that you can't possibly know from the course materials alone, outside/supplemental learning is highly encouraged. If you get stuck in lab scenario, read a **portion** of the walkthrough included with the lab and then resume your lab challenge without reference to the rest of the walkthrough. Only consult the walkthrough when you are absolutely stuck. This will help you develop research skills which will serve you well in the future. 

I did each lab (excluding the Linux and Web Application labs) roughly 10 times and was able to logically explain the reasoning behind each step. I felt ready for the exam after 3 months of playing in the labs, I could not have been more wrong. To this day, I cannot really explain my disregard for the Linux and Web Application materials but at the time my intuition told me to focus on the network pivoting and windows exploitation techniques taught in the course and that would suffice (LOL). 

The exam structure is as follows: you get one week to complete a simulated penetration test on a corporate network and then another week to compose your penetration testing report. One thing (among others) that sets eLearnSecurity apart from other vendors is their emphasis on reporting. This is truly a course aimed at aspiring penetration testers. 

The exam absolutely destroyed me. I spent probably close to 70 hours on the keyboard during that week learning a lot of concepts for the first time since I was underprepared and barely managed to pass by the end of it. I totally underestimated the difficulty of the exam. Keep in mind I was woefully underprepared for the course in general and took a haphazard approach to the exam preparation so don't be like me, study every single module and know it like the back of your hand. 

To date, this was probably my roughest exam experience, this and OSCE. Simply knowing how the lab scenarios work is not enough, you will need to think creatively, be thorough, and be able to research and learn new concepts on the fly.

PROS:
+ Excellent theory presentation;
+ Excellent hands-on labs that reinforce theory;
+ Emphasis on concepts/skills that matter for professional penetration testers;
+ Information that touches on concepts not usually found in free training materials/CTFs such as reconnaissance and OSINT;
+ Huge emphasis on Metasploit usage; and
+ Huge emphasis on pivoting. 

CONS: 
+ Expensive;
+ Relatively unknown as far as certfications go, but is picking up steam in the InfoSec community;
+ You don't really develop a testing methodology because the labs are so concept-focused, it lacks the playground of a VirtualHackingLabs or PWK/OSCP. 

### Final Verdict
I would absolutely recommend this course to anyone looking to break into penetration testing. In fact, I would say to anyone out there that knows for certain they want to be a penetration tester to either start with this course or start with their subordinate course the PTS/eJPT and then eventually take the PTP/eCPPT. I cannot overstate how important this course/certification was to my skill development.

I spent about 150 hours total in this course, at the time it felt like a huge time investment. That is because I hadn't yet done OSCP :) 

## OffensiveSecurity Certified Professional (OSCP) (November 2018 - Janurary 2019)
I won't spend much time describing my PWK/OSCP experience in this space as I have already written a stand-alone review of it [here:](https://h0mbre.github.io/OSCP/). Altogther, I spent about 300 hours preparing for the exam and rooted around 100 boxes between my efforts in the OSCP labs, the Virtual Hacking Labs environment, Hack the Box, and Vulnhub. I really felt like my experience with eCPPT allowed me to hit the ground running in OSCP and allowed me to maximize my time in labs instead of digesting the materials.

PROS:
+ Exposure to a ton of different exploitation techniques;
+ Exposure to a lot of different technologies;
+ Opportunity to develop a dependable testing methodology;
+ Opportunity to develop research skills;
+ Development of a problem-solving mindset;

CONS:
+ Dated materials and technolgies;
+ Virtually no coverage of Active Directory;
+ Limited exposure to client-side attacks.

### Final Verdict
Out of all of the certifications and trainings mentioned thus far, I would recommend this one the most. It is very broad and will not make you an expert in anything and you will definitely not be able to walk right into a penetration testing role and begin performing; however, it does give you a solid foundation and a great mindset. If you're going to spend money on just one certification, let it be this one. 

## eLearnSecurity Web Application Penetration Testing (eWPT) (February 2019 - April 2019)
Again, I won't spend much time describing my eWPT experience in this space as I have already written a stand-alone review of it [here](https://h0mbre.github.io/eWPT/). eWPT really helped me solidify my understanding of SQLi and XSS fundamentals. It also taught me some great web application enumeration fundamentals and some new tricks for BurpSuite that I hadn't seen before. I think you could conceivably take this course before eCPPT or OSCP but it will be pretty difficult in that case. It was great for getting acquainted with web application testing fundamentals. 

Once again, I underestimated the exam and got owned. Luckily, I was able to breakthrough on day 3 after much frustration and reach the final objective. This course was very fun. 

PROS:
+ Exposure to web app testing fundamentals;
+ Exposure to BurpSuite;
+ Exposure to web app enumeration techniques;
+ Exposure to web app technologies such as SOAP, CORS, etc. 

CONS:
+ Material covering same concepts is readily available for free because of huge Bug Bounty community;
+ Somewhat dated material. 

### Final Verdict
I thought the course was great and really helped me solidify some gaps in my web app knowledge that I had after OSCP and doing Hack the Box sporadically. I would recommend this to anyone who knows that they want to specifically do web app testing and wants a solid grasp of the fundamentals in a structured environment. Otherwise, I think you can achieve the same level of competency with just reference to open-source/free materials that exist on the internet such as the bWAPP vulnerable VM and Bugcrowd's tutorials. 

## Pentester Academy's Security Linux Assembly Expert x86 (SLAE) (April 2019 - June 2019) 
Again, I won't spend much time describing my SLAE experience in this space as I have already written a stand-alone review of it [here](https://h0mbre.github.io/SLAE_x86_Review/). 

PROS:
+ Exposure to x86 Assembly;
+ Exposure to writing shellcode for Linux;
+ Flexible, outstanding exam structure that allows you to learn as much, if not more than you did during the course;
+ Includes course on using GDB debugger; 
+ Extremely affordable; 

CONS:
+ Can't think of any

### Final Verdict
As I said in my course review, this is my favorite course ever. I had so much fun doing this course and writing the blog post solutions for the exam. I don't know that this certification is for everyone but I know for a fact that it was an outstanding on-ramp for OSCE and gave me more than enough Assembly knowledge to understand the concepts taught in OSCE. The course also helped me rediscover and refine some of my Python skills that had atrophied by this point. If you're interested in anything that deals with low-level programming: reverse engineering, shellcoding, exploit development, vulnerability research, etc, you need to take this course if you have no experience. I had no idea what Assembly was prior to this course and had a blast. 

## OffensiveSecurity Certified Expert (OSCE) (June 2019 - July 2019)
OSCE is the certification that corresponds to Offensive Security’s Cracking the Perimeter (CTP) course. According to the [CTP Webpage](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/), an OSCE will gain competencies in the following domains: 
+ Greater confidence in debugging Windows binaries,
+ Ability to work through encoding issues and space restrictions while crafting exploits,
+ An understanding of PE structure in order to learn techniques that backdoor executables and bypass AV,
+ Familiarity with more advanced protections like ASLR,
+ Increased comfort using creative and lateral thinking to achieve expanded view of standard vectors, and
+ Ability to think outside of the box in order to determine innovative ways of penetrating internal networks.

All of this is extremely fair in my opinion. In fact, you will know so much about these things you will want to cry at times 😊. 
After taking SLAE I jumped right into prep for CTP/OSCE. I blogged all of my preparation [here](https://h0mbre.github.io/). I spent a ton of time researching the exploit concepts and reading people’s blogs and spent tons of time in Immunity debugger. By the time CTP actually started for me I felt like most of the information was review. This was the goal though, I wanted to be overprepared. I think if you solely use the limited lab environment of CTP you will be in a tough spot come exam time. I recommend grabbing a Windows 7 VM from Microsoft and downloading Vulnserver as a bare minimum to supplementing your CTP lab work. 
My exposure to Assembly from SLAE was a huge factor for my success during CTP/OSCE, I can’t imagine coming into the course never having done any work in Assembly. 

In a lot of ways, OSCE was frustrating but the one I’m most proud of to date. For one, the materials and lab environment weren’t too robust. I think a lot of is expected of the student with regards to supplemental research, which is normally fine I just guess I had different expectations. This isn’t to say that I didn’t learn a bunch of useful techniques and tricks during the course, I definitely did, I would just say it’s less self-contained than say OSCP and by quite a bit. 

Secondly, the techniques you learn and the exploits you write aren’t very relevant for modern applications/operating systems. The exploit development you learn was relevant around 2010. This is fine since you have to start somewhere. I wouldn’t expect to say “I want to learn Windows exploit development” and then jump immediately into trying to piece together a reliable RCE exploit for the BlueKeep vulnerability; however, even after taking and passing the course I really can’t do anything lol. I would say OSCE is more like a gateway drug than anything else. This course got me hooked on exploit development and I plan on going further down this path. This course got me addicted to the feeling of building an exploit from scratch and getting it to work. I wish discovering vulnerabilities was a larger focus for the course, but you do get some exposure to some very basic techniques. 

Overall, I recommend the course for the sheer challenge of the exam. It was really quite different than anything I had done before. I found myself learning and doing things for the first time on the exam but it wasn’t as terrifying as I thought it would be. There was a confident calmness to it since throughout the course you learn related concepts and I put so much time into prepping for the course I knew that I could figure out how to do what was required. 

PROS:
+ narrowly focused and technical;
+ challenging;
+ gateway drug to advanced exploitation techniques;
+ unique certification that sets you apart on paper at least;
+ extremely fun;
+ exposure bug hunting;

CONS: 
+ dated exploit techinques/concepts;
+ labs/materials not as comprehensive/robust as PWK.  

### Final Verdict 
I would say, if you just want to know about Windows x86 buffer overflows, (and SEH, egghunters, alphanumeric shellcode, backdooring PEs, web application static code analysis, and Windows shellcoding, etc) then stick to books and blogs. However, if you want to set yourself apart on paper from the ever growing OSCP army and are looking for a challenge, I think the exam and certification are great for you. I’m very happy I took the course and was able to get through the exam, it has inspired me to continue learning. 

## Lessons Learned 

### Why Get Certs? 

I would say the main lesson I learned on my journey was that you need to cultivate an ability to self-learn. The amount of free resources out there for any security topic is overwhelming. A certification course in my opinion should: 
+ collate all of the relevant information and present it to students in a digestible format, and
+ have an instructor/teaching style which anticipates student’s learning difficulties/roadblocks and effectively mitigates them. 

If a certification course does not do these two things, then the only reason left to take the course and get the certification is because it is needed for a resume. 

### If You Only Get One

If you were only going to do one certification from this list with the goal of breaking into security, I would probably lean towards the OSCP for a few reasons. It’s a great entry-level certification in my opinion because it doesn’t bog students down in overly technical information, exposes them to a wide variety of techniques and technologies, and instills a good work ethic and resiliency you need to learn in the field. You get actual practical skills out of the course/certification. Secondly, it has great name recognition and will enable you get interview opportunities. 

### What I’d Do Differently

Since I came into this with zero background, I should’ve taken more care to get more familiar with Windows or Linux. If I was going to go the certification route, I should’ve done something like the Red Hat Certified System Administrator (RHCSA) or one of the Microsoft MCSE certifications. If not the actual certification, then at least spend time digesting and learning the materials. More detailed knowledge about these operating systems would’ve served me extremely well during my journey. To this day there are very simple things about both operating systems that I don’t know.  Knowing what I know now, I would probably take back the time spent on Sec+, Net+, and CEH and spend that time instead on learning one of the operating systems from a sysadmin perspective and spent time learning to program in C or C++. I think I’d be way ahead of my current self if I had done those things instead. 

### Optimized Path 

One underappreciated resource in my opinion is [Virtual Hacking Labs] (https://www.virtualhackinglabs.com/). The materials and lab environment are extremely similar to PWK/OSCP. The systems in the lab are more up to date as well. For a month pass the price right now is $99 compared to certification courses which cost thousands.

I think a great path for someone who wants to get into security and build a good foundation would be to do the following: 
1.	One of the aforementioned sysadmin certifications or something similar;
2.	a free intro to programming course (codeacademy has plenty);
3.	Virtual Hacking Labs 3 month pass;
4.	PWK/OSCP.

From here, I think you could go a number of different ways based on your interests. This curriculum obviously has some huge knowledge gaps (networking for example), but I think you would be ahead of where I was at the same point. Obviously if you don’t need the certifications and are only interested in the skillset, then just study the related/relevant materials. 

## Conclusion

Just wanted to give my take on the training I have done so far and potentially save some from making the same mistakes I felt I made. Again, none of this is fact, this is all simply my opinion. It's entirely possible I'm 100% wrong about everything I wrote and I did in fact take the best route during my training and I'm simply doing the 'grass is always greener' bit. I would just generally tell people going forward that you need to make sure the certification is offering you something that self-study will not or that it is required to get past HR for a position you want. As long as it's doing one of those things, it should be fine to take! Just don't underestimate your ability to self-learn. 
