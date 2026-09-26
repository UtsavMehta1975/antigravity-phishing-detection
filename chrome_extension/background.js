chrome.runtime.onInstalled.addListener(() => {
  console.log("ParallelAI Phishing Guard Installed and Active.");
});

// Listen for tab updates (when a user navigates to a new URL)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only trigger when the page has fully loaded and it's a real web URL
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith("http")) {
    
    // NOTE: Replace this with the live Render URL once deployed!
    const BACKEND_URL = "http://127.0.0.1:1511/api/scan/url";

    try {
      const response = await fetch(BACKEND_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: tab.url })
      });

      const data = await response.json();

      if (data.verdict === "MALICIOUS") {
        // If the backend flags it as malicious, inject a massive warning overlay into the page
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          func: (confidence) => {
            // Check if warning already exists to prevent duplicates
            if (document.getElementById('parallelai-warning-overlay')) return;

            const overlay = document.createElement("div");
            overlay.id = "parallelai-warning-overlay";
            overlay.style.position = "fixed";
            overlay.style.top = "0";
            overlay.style.left = "0";
            overlay.style.width = "100%";
            overlay.style.height = "100%";
            overlay.style.backgroundColor = "rgba(255, 0, 0, 0.95)";
            overlay.style.color = "white";
            overlay.style.zIndex = "999999999";
            overlay.style.display = "flex";
            overlay.style.flexDirection = "column";
            overlay.style.justifyContent = "center";
            overlay.style.alignItems = "center";
            overlay.style.fontFamily = "Arial, sans-serif";
            
            overlay.innerHTML = `
              <h1 style="font-size: 3rem; margin-bottom: 20px;">🚨 WARNING: MALICIOUS SITE DETECTED 🚨</h1>
              <p style="font-size: 1.5rem; margin-bottom: 30px;">ParallelAI & VirusTotal have flagged this website as highly dangerous.</p>
              <p style="font-size: 1.2rem; margin-bottom: 40px;">Risk Confidence Score: <strong>${confidence}%</strong></p>
              <button id="parallelai-go-back" style="padding: 15px 30px; font-size: 1.2rem; background: black; color: white; border: none; cursor: pointer; border-radius: 5px;">Get Me Out Of Here</button>
              <br><br>
              <a id="parallelai-proceed" href="#" style="color: #ffcccc; font-size: 0.9rem; text-decoration: underline;">I understand the risks, proceed anyway (Not Recommended)</a>
            `;

            document.body.appendChild(overlay);

            document.getElementById("parallelai-go-back").addEventListener("click", () => {
              window.history.back();
            });

            document.getElementById("parallelai-proceed").addEventListener("click", (e) => {
              e.preventDefault();
              overlay.remove();
            });
          },
          args: [data.confidence_score]
        });
      }
    } catch (error) {
      console.error("Error communicating with ParallelAI backend:", error);
    }
  }
});
