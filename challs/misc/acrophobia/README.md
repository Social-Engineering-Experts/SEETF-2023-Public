# Acrophobia

**Author**: YongJunLim

**Category**: Misc

Flag: `SEE{t1m3_t0_5crub_my_cr0pp3d_ph0t05_eU2ieeBV1HRZSXTi1FGMSojdHik8eLg1}`

## Description

I have a~~n extreme or ir~~rational fear of heights, even when I'm not particularly high up. It seems like every other day someone is ~~helping~~ pushing me in hopes that I would fall from a window. That's why I dislike being exposed to heights, including in images. I'll crop all heights out of my sight.

## Difficulty

Easy

## Solution

1. Based on the challenge name, it can be inferred that the image is related to the [aCropalypse vulnerability](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html).

2. A Google search for the image's filename `photo-1524821065909-083ad70f4743` would lead to the original photo hosted on [Unsplash](https://unsplash.com/photos/hUMiGZB0vJU) and the [direct image link](https://images.unsplash.com/photo-1524821065909-083ad70f4743?auto=format&fit=crop&w=2268&q=80). The aspect ratio suggests that the original photo had a height of 4039px and width of 2268px.

3. Using `exiftool` would show that there is trailer data after the IEND chunk. In addition, the colour type of the image is RGBA, suggesting that it might have been made with [Windows 11's Snipping Tool/Windows 10's Snip & Sketch](https://twitter.com/David3141593/status/1638222624084951040).

4. When using the [Python script](https://gist.github.com/DavidBuchanan314/93de9d07f7fab494bcdf17c2bd6cef02) written by one of aCropalypse's discoverers, the original dimensions should be given and the colour type should be set to RGBA.

```
Found 12855829 trailing bytes!
Extracted 12846389 bytes of idat!
building bitstream...
reconstructing bit-shifted bytestreams...
Scanning for viable parses...
Found viable parse at bit offset 72666!
Generating output PNG...
Fixing filters...
Done!
```

5. Near the top right of the recovered image, there would be a [Pastebin link](https://pastebin.com/raw/5DWc4ycv) containing the flag.
