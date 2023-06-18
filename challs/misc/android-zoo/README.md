# Android Zoo

**Author**: TheMythologist

**Category**: Misc

Flag: `SEE{PIGeon4ever:95184}`

## Description

```
Who knew pigeons could use Android phones?

This sus pigeon stored the flag on 2 phones, and the flag format is SEE{<password>:<gesture_pattern>}.

For example, if the password is `password` and the gesture pattern is `1337`, the flag is `SEE{password:1337}`

Hint: Don't worry, the password is in rockyou!

Side note: why aren't there any pigeons in zoos?
```

## Difficulty

Medium

## Solution

1. First device
    - Android 6.0, gesture/pattern-protected
    - Hash: scrypt(16384 rounds, block size (n) of 1, parallelism factor (p) of 8)
    - `gatekeeper.pattern.key` format
        - Meta Information - First 17 bytes
        - Salt - Next 8 bytes
        - Signature - Last 32 bytes
    - Pattern length: 5 (can be extracted from `device_policies.xml`)
2. Second device
    - Android 5.1, password-protected
    - Hash: SHA1 and MD5 hashes of salted password, concatenated together
    - Salt is located in sqlite3 `locksettings.db`, can be extracted using the following SQL query:

        ```sql
        SELECT "value" FROM "locksettings" WHERE "name" = 'lockscreen.password_salt';
        ```

    - Password length: 11 (can be extracted from `device_policies.xml`)

Possible open-source tool: [Android-Cracker](https://github.com/TheMythologist/android-cracker) :)
