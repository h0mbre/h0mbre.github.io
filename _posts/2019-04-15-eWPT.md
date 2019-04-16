---
layout: single
title: eLearnSecurity's Web Application Penetration Testing (WAPT/eWPT)
date: 2019-4-15
classes: wide
header:
  teaser: /assets/images/eLS/logo.png
tags:
  - eLearnSecurity
  - eWPT
  - WAPT
  - Penetration Testing
--- 
![](/assets/images/eLS/logo.png)

## Managing Expectations
I enrolled in WAPT because, beyond the narrow exposure to web app testing you get in PWK/OSCP, I had little to no experience. I have done ~30 machines on HackTheBox and found a lot of the skills I gained from HackTheBox and watching Ippsec walkthroughs to be very helpful during the course and exam. I really wanted to learn more about some of the client side type attacks that don't typically come up during CTF type activities. 

Prior to the course I read about half of the Web Application Hacker's Handbook and found the material to be outstanding, I actually referenced it a lot during the eWPT exam. I took my time during the course to make sure I was really grasping the concepts and not just rushing to add a certification to my CV. All in all, I probably spent around 70 hours in the various labs and way less than that reading through the material. I think the course is set up perfectly for those with little to no web app testing experience looking to get a solid grasp of the fundamentals. It really helped me get a better understanding of Cross-Site Scripting and SQL Injection in particular. The chapters on Session Security and Web Services were also great. 

I definitely recommend this course to anyone who can afford it and is interested in learning the web app testing fundamentals.   

If you're interested in the course or enrolled and have questions, please reach out to me on Twitter, HackTheBox, or NetSecFocus. I’d love to hear from you. 

## Prerequisites 
The eLearnSecurity syllabus recommends the following student prerequisites:
+	Basic understanding of HTML, HTTP, and JavaScript
+ Reading and understanding PHP code will help although it is not mandatory
+ No web development skills required

For the most part, I found these prerequisites to be accurate. I didn't really have a good understanding of HTML or JavaScript coming into the course (still don't have a good understanding of JavaScript, what the hell even is JavaScript) and was totally fine. The only time I wished I knew more JavaScript was during the chapters on HTML5 CORS misconfigurations as some of the exploit vectors require an actor to create a malicious webpage with a JavaScript payload. You don't do much PHP code reading or writing during the course. 

If you want to go the overkill route, you can take the Intro to JavaScript course on Codeacademy and read the Web Application Hacker's Handbook before the course. I also recommend downloading and playing with the bWAPP VM, the practical experience of the VM is very similar to the WAPT labs. Basic knowledge of the Linux command line is also a prerequisite that I feel you must have to get the most out of the class. I would also work to get some prerequisite knowledge of Burp Suite before taking the course.

**If you have limited Burp Suite experience, watch the 'Introduction to Burp Suite' Bugcrowd Univerity YouTube video linked below in 'Resources.'**

## Materials
The WAPT materials are pretty great. Depending on what version of the course you buy, you get a PDF/Slides of all the written material, videos demonstrating the concepts taught in the material, and then labs which correspond to each lesson in the material.

Most of the material was written/composed from 2013-2015. I believe the 2nd Edition of the Web Application Hacker's Handbook was published in 2011 so it makes really good supplemental learning material. 

The labs come in a few different flavors. All modules will have 'Lab Excercises' and most will also have 'Challenges.' The Lab Exercises come with solutions that you can reference when you get stuck, the Challenges do not and are meant to push the student into self-study territory and thinking outside of the box. I highly highly recommend doing all the Challenges. Usually if you get stuck on a Challenge, you can search the forums for previous students getting stuck at the same point and read those threads. You can also leverage the community and ask people in whatever online forum you're a part of. The Lab Excercises will only cover the bare minimum required for you to understand the concepts at a high-level so I wouldn't recommend only doing the Lab Excercises. 

Some of the modules also come with lab access to the web applications that are demo'd in the instructional videos. For instance, if the instructor in the video is going against FooSite.com, you will sometimes have access to FooSite.com in the lab environment. This is good for those who like to watch and play along with the instructor in the video. 

One of the unique things about the material is that eLS takes some time to explain to you why vulnerabilites exist and how to mitigate them. I found this part of the material to be really interesting. eLS also explains how/why vulnerabilities exist and delves somewhat into ambiguous topics related to pentesting such as who's responsibility it is to mitigate certain classes of vulnerabilities. There are several instances where there is clearly a victim of an attack but not a clear responsible party. 

## Going Through The Course
I found that the order of the modules was perfectly fine, it never felt like they were out of order or that one module late in the course would've helped with an earlier module had the order been different. I recommend reading through all the material for a module first before going to the lab exercises which correspond to the material. 

When it comes to the lab exercises, I would try your best to avoid the spoilers in the back of the PDF explaining the solutions. The lab excercises should not be difficult if you truly grasped the concept from the materials. If you get stuck on a lab exercise, just head back to the course material and see if you can find the solution there, usually you can. Typically there isn't a large disconnect between the examples in the materials and the environments in the lab. 

I found the Challenges to be much tougher than the lab exercises, as you would expect. Don't fret if you find yourself getting owned by the Challenges, they're supposed to be harder. Just take your time, consult outside resources, try to google for help, and look for the Challenge title in the Student Forums if all else fails. To get the most out of the course I definitely recommend doing the Challenges. 

## The Exam
The exam is structured as follows: 7 days of VPN access to the test environment followed by 7 days to compose your penetration test report. 

The exam guidance is careful to emphasize that the exam is not a CTF, it is a simulated penetration test. There is a 'required but not sufficient' goal which you must reach. If you leverage X, Y, and Z vulnerabilities to get to the required goal, but do not document the existence of A, B, C vulnerabilities in your report, you will fail. So even if you do not leverage a vulnerability during the engagement, make sure you document its existence in your report.

Your report has to be robust and include mitigation strategies as well as exploitation proofs. Definitely familiarize yourself with the eLS reporting guide before clicking 'Start' on your certification exam. 

The exam had me stuck at a particular spot for a couple of days, it was very frustrating. But, as it usually turns out, I had overlooked a small detail and the solution was not overly complex in any way, I had simply not been thorough enough in my testing methodology. You have plenty of time for the testing performance, so be thorough. I had reached the final goal of the test by the 4th day, but you could conceivably do everything in a single day or two if you're well prepared. If you get stuck do not worry, just take your time and refer back to the course materials if needed. If you think a particular exploit technique should be working, but it's not, see if you can find an analogous example in the course materials or online. Security Stack Exchange often has good questions and answers. 

## Conclusion
I think this course is perfect for the inexperienced/aspiring web app tester. The fact that the materials are semi-dated (~2015ish for most) doesn't seem like an issue to me as these vulnerabilities still exist. Professional bug bounty hunters have been publicly plugging the Wep App Pentesters Handbook as late as 2019, so I don't think the age of the materials is a huge demerit. I think you could reasonably take this course before any other practical pentesting course (like PTP/eCPPT or PWK/OSCP) and be fine. I was happy to close some of the gaps in my knowledge with this course. Some of the material was indeed a review, but even then, I still learned some things in those modules (File/Resource Attacks comes to mind). 

## Resources
+ [Web Application Hacker's Handbook (2nd Edition](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470)
+ [bWAPP Vulnerable Web Application VM](http://www.itsecgames.com/)
+ [bWAPP Walkthroughs](https://www.scribd.com/document/385323969/bWAPP#fullscreen&from_embed)
+ [Bugcrowd University Introduction to Burp Suite](https://www.youtube.com/watch?v=h2duGBZLEek)
+ [Bugcrowd University XSS](https://www.youtube.com/watch?v=gkMl1suyj3M)
+ [Bugcrowd Universty Broken Access Controls](https://www.youtube.com/watch?v=94-tlOCApOc)
+ [Intro to JavaScript -- Codeacademy](https://www.codecademy.com/learn/introduction-to-javascript)
+ [Portswigger Web Security Academy](https://portswigger.net/web-security)



