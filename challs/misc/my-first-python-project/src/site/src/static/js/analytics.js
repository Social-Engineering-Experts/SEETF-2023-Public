chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.fetchUrl) {
        fetch(request.fetchUrl, { method: "GET" })
            .then((response) => sendResponse({ status: response.ok }))
            .catch(error => sendResponse({ status: false, error: JSON.stringify(error) }))
    }
    return true
})