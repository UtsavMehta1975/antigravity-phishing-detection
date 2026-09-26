document.addEventListener("DOMContentLoaded", async () => {
  const urlDisplay = document.getElementById("url-display");
  const scanBtn = document.getElementById("scan-btn");
  const loading = document.getElementById("loading");
  const resultDiv = document.getElementById("result");

  let currentUrl = "";

  // Get current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0) {
      currentUrl = tabs[0].url;
      urlDisplay.textContent = currentUrl.length > 60 ? currentUrl.substring(0, 60) + "..." : currentUrl;
    }
  });

  scanBtn.addEventListener("click", async () => {
    if (!currentUrl || currentUrl.startsWith("chrome://")) {
      resultDiv.style.display = "block";
      resultDiv.className = "safe";
      resultDiv.textContent = "Safe: Internal Browser Page";
      return;
    }

    scanBtn.style.display = "none";
    loading.style.display = "block";
    resultDiv.style.display = "none";

    try {
      // NOTE: Replace with Render URL when deployed
      const BACKEND_URL = "http://127.0.0.1:1511/api/scan/url"; 
      
      const response = await fetch(BACKEND_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentUrl })
      });

      const data = await response.json();
      
      loading.style.display = "none";
      scanBtn.style.display = "block";
      resultDiv.style.display = "block";

      if (data.verdict === "MALICIOUS") {
        resultDiv.className = "malicious";
        resultDiv.innerHTML = `🚨 MALICIOUS THREAT DETECTED!<br><br>Risk Score: ${data.confidence_score}%`;
      } else {
        resultDiv.className = "safe";
        resultDiv.innerHTML = `✅ SAFE PAGE<br><br>Risk Score: ${data.confidence_score}%`;
      }
    } catch (error) {
      loading.style.display = "none";
      scanBtn.style.display = "block";
      resultDiv.style.display = "block";
      resultDiv.className = "malicious";
      resultDiv.textContent = "Error connecting to AI backend. Make sure the server is running.";
    }
  });
});
