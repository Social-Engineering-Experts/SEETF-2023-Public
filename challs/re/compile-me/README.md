# CompileMe

**Author**: Neobeo

**Category**: RE

Flag: `SEE{h0w_lon9_did_1t_t4ke_to_c0mp1le_m3_d544d03f5a376fc771d804262712a9a1}`

## Description

Sourceless binaries are so last gen. Here's a binaryless source, but beware: compiling the code might take longer than you are willing to wait.

## Difficulty

Medium

## Deployment

NIL

## Solution

This is a thinly veiled sudoku. The original grid is

```
800000000003600000070090200050007000000045700000100030001000068008500010090000400
```

which we can actually find online and has the unique solution

```
812753649943682175675491283154237896369845721287169534521974368438526917796318452
```

which we can convert back to the .NET types. Now the key is just the concatenations of all the `typeof(T).Name`, so we can solve this with a C# script:

```
var types = new[] { typeof(bool), typeof(byte), typeof(sbyte), typeof(short), typeof(ushort), typeof(int), typeof(uint), typeof(long), typeof(ulong) };
var key = string.Concat("812753649943682175675491283154237896369845721287169534521974368438526917796318452".Select(i => types[i - '1'].Name));
var enc = Convert.FromBase64String("To8nQU1OWzL4qzlMYUPPeCI68VIueVeBrtZYuNkHv5TfVXoriYjNIW23S0DHdPNQW84enVObbXmPF6O1xs1+9MiWVAu6T39L");
Console.WriteLine(string.Concat(new System.Security.Cryptography.Rfc2898DeriveBytes(key, 0).GetBytes(99).Zip(enc, (a, b) => (char)(a ^ b))));
```