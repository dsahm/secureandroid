# secureandroid
A small library for encrypting and storing data securely on Android devices.

This is version 1.0-beta, ONLY for testing purposes.

If you use ProGuard, you need to add the following rule:

-keep class my.secureandroid.PrngFixes$* { *; }
