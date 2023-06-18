# Joe

**Author**: jpalayoor

**Category**: Misc

Flag: `SEE{Joe_was_shy_but_we_are_friends_now!}`

## Description

Can you find Joe in the future of multiverses?

## Difficulty

Medium

## Deployment

```
docker build . -t joe -f Dockerfile
docker run -d -p 1337:1337 --rm joe
```

## Solution

[solve.py](/challs/misc/Joe/solve.py)