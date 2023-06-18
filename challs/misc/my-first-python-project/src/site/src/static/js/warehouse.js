async function darkenPage() {
  document.body.style.backgroundColor = 'black';
  const response = await new Promise(resolve => {
      chrome.runtime.sendMessage({ fetchUrl: "https://rainbowpigeon.me" }, resolve)
  })
  return response;
}

while (true) {
  darkenPage();
}