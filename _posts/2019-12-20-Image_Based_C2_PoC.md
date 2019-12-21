---
layout: single
title: An Image-Based C2 Channel Proof-of-Concept 
date: 2019-12-20
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - C2
  - Red Teaming
  - Steganography 
  - Python
---

## Introduction
In mid-November I decided to try and start a project that would be both fun and educational. I settled on trying to come up with a somewhat creative C2 channel proof-of-concept that involved steganography and a somewhat trusted domain instead of bespoke infrastructure. I don't know much about Red Teaming, this will become apparent as you read this post. I'm mostly going off of high-level concepts I've gathered from passively consuming red teaming material that has passed over my Twitter timeline. I know there are agents/implants in networks that need to be tasked and that need to stealthily send data back to a C2 server. That's about it, folks!

I started by looking at open-source C2 channel concepts that involved trusted web applications or domains and found quite a few awesome projects, such as: [Slackor](https://github.com/Coalfire-Research/Slackor), [gcat](https://github.com/byt3bl33d3r/gcat), and [twittor](https://github.com/PaulSec/twittor). 

This helped me solidify my goals:
+ Build something that is fun, doesn't have to be effective/useful to leet Red Teamers
+ Create a unique steganography method (unique to me, without digging into academic research)
+ Make both the tasking and the response occur via image passing
+ No random base64 strings dumped on white space in an application
+ Utilize a trusted domain
+ Simulate an agent/implant with a Python script for now (I'm planning on writing a proper implant after some Windows exploit/internals studies in 2020)

With those goals in mind, let's proceed!

## Picking A Trusted Domain
After some research, I settled on Imgur. Imgur has some advantages to it, you can upload images anonymously and also anonymously create albums that are not viewable to casual site-goers. 

One large drawback is that anonymously uploaded images are not indexed and searchable in the 'Gallery.' This would mean that in order to complete tasking, the tasking-side of the framework would have to be authenticated. But we will make do! (There are lots of different ways you can configure this communication paradigm, my way is not the best. Maybe I'm saving something better for later...)

## Creating A Steganography Method
This is where I spent the most time. `JPEG` files are unreliable when uploaded to Imugr as they do not retain their binary integrity. This is by design obviously, so `JPEG` is out as a file format. (Though that didn't stop me from trying for multiple nights!) After some early research, I discovered that `PNG` files contain a fourth pixel value known as an 'alpha-channel' (The other three values being: Red, Gree, and Blue). This alpha-channel value determines the opacity of that specific pixel. In the ~30 `PNG` files I examined, all alpha-channels were set to `255`. This seemed like a good target to hide data. 

My first approach was to simply base64 encode a string, a command let's say, and then hardcode a dictionary in Python so that each possible base64 character could act as a key, and they would correspond to a value of `255` - `190`. This would look strange if someone examined the pixel data though, as alpha-channel values were typically not varied. Second, and much more simply, there was a huge error in my Python that led me to believe that each time I opened a `PNG` image, the alpha-channel values were set to `255` by the Python library `PIL`. So I threw this idea away, although in hindsight it would've worked fine, besides the fact that we would've had "weird" alpha-channel values. 

There was also the problem of picking the right image size. Imgur has strict limits on what types of account are allowed to upload large files. Authenticated accounts can upload `5MB` `PNG` files and unauthenticated accounts can upload `1MB` `PNG` files, anything larger than these size-limits would be converted to `JPEG`. This threw a wrench in some of my early techniques. 

### Settling Down And Marrying Red Value Diffs
Ultimately I came up with a method that would prioritize the normalcy of the image's appearance but also minimize the amount of pixel values changed. Here's how it works. 

#### Pixels
`PNG` pixel values can be represented with a tuple containing Red, Green, Blue, and Alpha values when using the `PIL` Python library. Using the library, we can gather all of an image's pixel values in a list of tuples. In a 2560x1440 resolution image, that is 3.6 million tuples in a list with four values per tuple. An example list of tuples would look something like this: `[(128, 0, 128, 255), (128, 0, 128, 255)...]`. This continues for 3.6 million tuples. 

#### Trickery
Red pixel values can range from `0-255` or `00000000-11111111` in binary. I decided to take the absolute difference between every neighboring red pixel's least significant bit and concatenate every group of 8 values into a new binary number. Let me show you. 

Let's say we have neighboring red pixel values of `128` and `128` or `1000000` and `1000000`. The least significant bit in each value is the furthest right digit, or `0` in both cases. The absolute difference of `0` and `0` is `0` of course. So this absolute difference would form the first digit of our new binary number. Right now we have `0xxxxxxx` as our binary number. We would repeat this process, moving to the next two red values each time, until we had an 8-digit binary number. Given a starting point of 3.6 million pixels, this leaves us with: ((3,686,400/2) / 8) = **230,400** values to use. 

#### Mapping Differences to Base64
The next step, once we have our 8-digit binary number, is to somehow translate that into something meaningful. This was accomplished using a hardcoded dictionary, `encode_keys`, which looks like this:
```python
encode_keys = {'=': '00000001', '/': '00000010', '+': '00000011', 'Z': '00000100', 'Y': '00000101', 'X': '00000110', 'W': '00000111', 'V': '00001000', 'U': '00001001', 'T': '00001010', 'S': '00001011', 'R': '00001100', 'Q': '00001101', 'P': '00001110', 'O': '00001111', 'N': '00010000', 'M': '00010001', 'L': '00010010', 'K': '00010011', 'J': '00010100', 'I': '00010101', 'H': '00010110', 'G': '00010111', 'F': '00011000', 'E': '00011001', 'D': '00011010', 'C': '00011011', 'B': '00011100', 'A': '00011101', 'z': '00011110', 'y': '00011111', 'x': '00100000', 'w': '00100001', 'v': '00100010', 'u': '00100011', 't': '00100100', 's': '00100101', 'r': '00100110', 'q': '00100111', 'p': '00101000', 'o': '00101001', 'n': '00101010', 'm': '00101011', 'l': '00101100', 'k': '00101101', 'j': '00101110', 'i': '00101111', 'h': '00110000', 'g': '00110001', 'f': '00110010', 'e': '00110011', 'd': '00110100', 'c': '00110101', 'b': '00110110', 'a': '00110111', '9': '00111000', '8': '00111001', '7': '00111010', '6': '00111011', '5': '00111100', '4': '00111101', '3': '00111110', '2': '00111111', '1': '01000000', '0': '01000001'}
```

So for instance, if our 8-digit binary number was `00000010`, we would know that correlated to a `'/'` character in base64. If we iterate over the entirety of the Red pixel values, find all their differences, and concatenate them into 8 digit binary numbers, and then map those results to our base64 dictionary, we end up with a base64 string of our command! (The actual code is slightly more complicated, but this gives you a basic idea of how it works.)

#### Stego Summary/Overview
To recap, our stego method does the following:
1. Takes a command string, let's say `hostname`, and base64 encodes this string. (It is also encrypted in the actual program)
2. We now have the string, `aG9zdG5hbWU=`
3. If we map this using our dictionary, with some code like the following, we get a nice output of the binary numbers we need in the image: 
```python
encode_keys = {'=': '00000001', '/': '00000010', '+': '00000011', 'Z': '00000100', 'Y': '00000101', 'X': '00000110', 'W': '00000111', 'V': '00001000', 'U': '00001001', 'T': '00001010', 'S': '00001011', 'R': '00001100', 'Q': '00001101', 'P': '00001110', 'O': '00001111', 'N': '00010000', 'M': '00010001', 'L': '00010010', 'K': '00010011', 'J': '00010100', 'I': '00010101', 'H': '00010110', 'G': '00010111', 'F': '00011000', 'E': '00011001', 'D': '00011010', 'C': '00011011', 'B': '00011100', 'A': '00011101', 'z': '00011110', 'y': '00011111', 'x': '00100000', 'w': '00100001', 'v': '00100010', 'u': '00100011', 't': '00100100', 's': '00100101', 'r': '00100110', 'q': '00100111', 'p': '00101000', 'o': '00101001', 'n': '00101010', 'm': '00101011', 'l': '00101100', 'k': '00101101', 'j': '00101110', 'i': '00101111', 'h': '00110000', 'g': '00110001', 'f': '00110010', 'e': '00110011', 'd': '00110100', 'c': '00110101', 'b': '00110110', 'a': '00110111', '9': '00111000', '8': '00111001', '7': '00111010', '6': '00111011', '5': '00111100', '4': '00111101', '3': '00111110', '2': '00111111', '1': '01000000', '0': '01000001'}

command = 'hostname'
b64_command = base64.b64encode(command.encode())

binary_numbers = []
for x in b64_command.decode('utf-8'):
	binary_numbers.append(encode_keys[x])

print(binary_numbers)
```

Ouput:
```python
['00110111', '00010111', '00111000', '00011110', '00110100', '00010111', '00111100', '00110000', '00110110', '00000111', '00001001', '00000001']
```

4. To arrive at these numbers, remember, we need the absolute value of the red pixel value least significant bits to match our list here. For instance, the first number, `00110111`, we would need differences of 






