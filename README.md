# EAC-Kernel-Packet-Fucker
Not my code. Only for saving

This is the Easy Anti-Cheat Kernel Packet Fucker (for short, EACKPFucker).
What is this? Basically, packets via their kernel mode driver are not going to be sent to them, which means your pasta pasta 2023 kdmapper FUD bypasses can be used without any trouble.

Okay, you got me out of my pants. How the fuck does this work?
By simply changing one address. Now, let's dive deep into how EAC actually works.

From the beginning, Easy Anti-Cheat has to actually get your data in order to ban you. These packets are sent over their Hydra channel and are cryptographically secure. That is all you need to know for this bypass, I will not go into more detail about this.

Let's take a look at how this works inside their kernel driver, with a random violation:

![image](https://user-images.githubusercontent.com/13917777/173832205-99154956-9186-4edd-a9a0-654384856299.png)

Doesn't this look vulnerable to you? Because it sure does to me.
Let's take a look at our first function: kalloc_rt
![image](https://user-images.githubusercontent.com/13917777/173832254-ecdf64c9-2524-4248-9810-305dba0573a3.png)
Hmm, okay. Let's jump into alloc_pool_with_tag
![image](https://user-images.githubusercontent.com/13917777/173832337-8fb57475-8e45-478b-8390-f31d1b51868e.png)
It dynamically imports ExAllocatePoolWithTag. Hmmmm... I wonder what would happen if someone were to modify that qword to their modified malloc function... (yeah, it works -- and since you're modifying a writable section, EAC is none the wiser)

Okay, now we have control over memory allocation. Cool! What can we do with this?

I'm glad you asked! Here's the thing: All packets from kernel mode are the size of 33096i64.. aaand previously, we saw that if the memory doesn't get allocated, EAC just.. ignores the violation.

Okay, say someone was to simply.. do this:

![image](https://user-images.githubusercontent.com/13917777/173832960-7e26cb65-5752-4a6c-9e04-a31075f9382d.png)

![image](https://user-images.githubusercontent.com/13917777/173832390-4483329e-0a5a-45a6-90d7-49b203f4677b.png)

![image](https://user-images.githubusercontent.com/13917777/173832413-ec97bc29-0dc2-40dd-b3e6-c4d9f3480bdd.png)



