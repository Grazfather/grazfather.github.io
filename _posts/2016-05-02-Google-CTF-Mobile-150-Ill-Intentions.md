---
layout: post
title:  "Google CTF - Mobile 150 - Ill Intentions"
date:   2016-05-02 12:00:00 -0800
categories: ctf re mobile
---

The timing for this challenge was just about perfect for me. A new colleague of mine just last week did a presentation on smali basics and debugging Android Applications using IDA. Before that I had only done some of the most basic patches in smali and no real dynamic stuff other than with `am` or purpose-built apps.

My process for an APK is pretty simple: Unzip, `dex2jar`, and `apktool -d`. This yields a _.jar_ file you can look at with JD-GUI and the smali code if you need to make changes. It also converts the _AndroidManifest.xml_ back into a readable format.

Peeking at the manifest, we see that it defines two permissions, _ctf.permission._MSG_, which has the level 'signature', and _ctf.permission._SEND_. There are also a few activities defined: _com.example.application.IsThisTheRealOne_, _...ThisIsTheRealOne_, and _...DefinitelyNotThisOne_. Finally, it defines a receiver _com.example.application.Send_to_Activity_.

Popping the jar into JD-GUI, we first peek at the _MainActivity_. Super simple: Nothing on the UI but some text, and the _Send_to_Activity_ receiver is registered, filtering on _com.ctf.INCOMING_INTENT_, and requiring the first custom 'MSG' permission.

In _Send_to_Activity_'s `onReceive` message we see that it checks the received intent for a string extra named "msg", and uses it to select which activity to send an intent to.

It's in the three activities that are sent to that things get interesting. All three look about the same, with small variations: Get some string, munge it up (using some native functions `computeFlag` and `definitelyNotThis` from _libhello-jki.so_), and then send a broadcast intent with the result. Because it doesn't take any input from us, we can assume that one of these must generated the flag, and it's only a matter of 'catching' the output.

Let's play around to make sure we have the correct understanding of what's going on. Installing the apk on my phone, I opened each of the activities using `am`:

{% highlight bash %}
shell@A0001:/ $ su
root@A0001:/ # am start -n com.example.hellojni/com.example.application.MainActivity
Starting: Intent { cmp=com.example.hellojni/com.example.application.MainActivity }
root@A0001:/ # am start -n com.example.hellojni/com.example.application.IsThisTheRealOne
Starting: Intent { cmp=com.example.hellojni/com.example.application.IsThisTheRealOne }
root@A0001:/ # am start -n com.example.hellojni/com.example.application.ThisIsTheRealOne
Starting: Intent { cmp=com.example.hellojni/com.example.application.ThisIsTheRealOne }
root@A0001:/ # am start -n com.example.hellojni/com.example.application.DefinitelyNotThisOne
Starting: Intent { cmp=com.example.hellojni/com.example.application.DefinitelyNotThisOne }
{% endhighlight %}

Although it took longer than I'd like to admit to get the syntax correct in `am`, once I had the above commands, I could switch between the activites with easy. The last three activities render on screen with nothing but a big button. Hitting the button executes the code that computes and broadcasts the flag. Note that we never had to use _Send_to_Activity_. We _could_ have used it just the same:

{% highlight bash %}
root@A0001:/ # am broadcast -a com.ctf.INCOMING_INTENT --es msg "IsThisTheRealOne"
Broadcasting: Intent { act=com.ctf.INCOMING_INTENT (has extras) }
Broadcast completed: result=0
{% endhighlight %}

Now that we know how to control the app and have a pretty good idea of how the flag is generated, there are a few ways to approach this:

1. We can write an app that has a receiver that filters on _com.ctf.OUTGOING_INTENT_ and logs what it receives.
2. We can debug the app and just set a breakpoint on each call to `putExtra`.

Because I don't feel like writing java (I never do), I'll go with the latter. The former requires signing the new app with the same key (because of the 'signature' level on the permission), but we could get around that by simply re-signing the original app with our own key. The latter requires we change the _AndroidManifest.xml_ to set `debuggable` to true. This also requires re-signing the app (so we can reinstall it) but that's trivial.

1. Edit _AndroidManifest.xml_: `<application android:icon="@mipmap/ic_launcher" android:label="CTF Application" android:debuggable="true">`
2. Build a new apk: `apktool b`
3. Create some bogus key: `keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000`
4. Sign the apk: `jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore ./my-release-key.keystore illintentions.apk alias_name`
5. Uninstall the old app (from the UI).
6. Install the new one: `adb install illintentions.apk`

Now I load up the APK in IDA, navigate to the `onClick` methods in each activity, set a breakpoint, follow the instructions [here](https://www.hex-rays.com/products/ida/support/tutorials/debugging_dalvik.pdf), and start the application in the debugger.

![Breakpoint]({{site.url}}/assets/2016-05-02-Google-CTF-Mobile-150-Ill-Intentions-1.png)

Once IDA has connected to the application (just skipping past the auto-set bps), and the app is running, I use `am` again to send one of the intents, then tap on the button that shows up. IDA should break immediately. Now at this point we see that the output of `perhapsThis`, which is fed directly to `putExtra` is stored in `v6`. Opening the 'Watch' view (Debugger -> Debugger windows -> Watch view), I simply created a new watch on `v6` that casts it to `Object *`.

![Flag]({{site.url}}/assets/2016-05-02-Google-CTF-Mobile-150-Ill-Intentions-2.png)

(Yes, I got lucky and chose the correct activity on my first try).

flag: CTF{IDontHaveABadjokeSorry}
