---
layout: post
title:  "Sharif CTF 2016 - RE100 ‘Android App’ Writeup"
date:   2016-02-14 15:00:00 -0800
categories: ctf re
---

This one I didn't actually solve in time, because I spent too much time trying to a) Use [frida](http://frida.re) and b) RE the args to the two import functions.

Because I am a fan of Frida (first cutting my teeth on it during the 2015 Flare On challenge), I decided I would use it in lieu of a bebugger for this challenge (I didn't want to figure out the toolchain to get the lldb client running on my mac).

Starting with `dex2jar` I took it apart and took a quick peek at the two main classes. They used JNI to call into function in the provided dynamic library, and then generate the flag based on that input. Because the flag is generated based on the output from one of the functions, but the other lets us know whether or not we succeeded, I spent almost no time on the java and went directly into looking at the native code.

Loading up the library in IDA, it was a little intimidating because of the unfamiliar ISA. I decided to try to do this dynamically, so this is when I decided `frida-trace` would be my friend.

![No thanks]({{site.url}}/assets/2016-02-14-Sharif-CTF-RE100-Android-App-1.png)

Setting up Frida is very straight forward:

{% highlight bash %}
adb install Sharif_CTF.apk
adb push frida-server /data/local/tmp
adb shell
su
/data/local/tmp/frida-server
{% endhighlight %}

I could then instrument the application and play around with it.

{% highlight bash %}
frida-ps -U|grep ctf
frida-trace -U -p <pid> -i '*isCorrect*'
{% endhighlight %}

I spent _way_ more time than I would like to admit here, playing with `Memory.read<X>` trying to read out the arguments and return value, but the problem was that this function is provided a Java string, whose structure I am unfamiliar part. Part of the complexity of the native functions are surely just getting the C string out of the `String` object, but I didn't figuring that out.

If I wanted to see what was going on _easily_ I'd want to find a function that takes C strings, which are easy to read from. Lucky for me, the `isCorrect` function import `strcmp` from libc.so. It can't be that easy... can it?

![Calling strcmp]({{site.url}}/assets/2016-02-14-Sharif-CTF-RE100-Android-App-2.png)

{% highlight bash %}
frida-trace -U -p <pid> -i '*strcmp*'
{% endhighlight %}

Editing the created strcmp.js:

{% highlight js %}
onEnter: function (log, args, state) {
    log("strcmp(" + Memory.readUtf8String(args[0]) + "," +  Memory.readUtf8String(args[1]) + ")");
},
{% endhighlight %}

And then just hitting 'Login' on the app:

{% highlight bash %}
  2059 ms  strcmp(Serial Number,ef57f3fe3cf603c03890ee588878c0ec)
{% endhighlight %}

Now, remember that this isn't the flag, but what is compared against to determine if we have the login. We could fake the retval from this function to return true, but that would make the flag generation fail. Instead, just enter 'ef57f3fe3cf603c03890ee588878c0ec' into the prompt and see the flag pop out.

![Flag]({{site.url}}/assets/2016-02-14-Sharif-CTF-RE100-Android-App-3.png)

Flag: Sharif_CTF{833489ef285e6fa80690099efc5d9c9d}
