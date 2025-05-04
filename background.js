// Security headers we track
const SECURITY_HEADERS = [
    'content-security-policy',
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-resource-policy',
    'cross-origin-opener-policy',
    'cross-origin-embedder-policy'
  ];
  
  // Data storage
  let headerStore = {};
  let extensionEnabled = true;
  
  // Initialize extension state
  browser.storage.local.get(['extensionEnabled', 'darkMode']).then((result) => {
    extensionEnabled = result.extensionEnabled !== undefined ? result.extensionEnabled : true;
    
    // Set defaults if needed
    if (result.extensionEnabled === undefined) {
      browser.storage.local.set({ extensionEnabled: true });
    }
    
    if (result.darkMode === undefined) {
      browser.storage.local.set({ darkMode: false });
    }
    
    updateAllIcons();
  });
  
  // Main request handler
  browser.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (!extensionEnabled) return { responseHeaders: details.responseHeaders };
      
      if (details.type === 'main_frame') {
        const url = new URL(details.url);
        const domain = url.hostname;
        
        // Extract security headers
        const securityHeaders = {};
        SECURITY_HEADERS.forEach(header => {
          const foundHeader = details.responseHeaders.find(h => 
            h.name.toLowerCase() === header
          );
          securityHeaders[header] = foundHeader ? foundHeader.value : null;
        });
        
        // Process and store data
        const score = calculateSecurityScore(securityHeaders);
        headerStore[details.tabId] = {
          domain,
          headers: securityHeaders,
          score,
          timestamp: Date.now(),
          url: details.url
        };
        
        updateIcon(details.tabId, score);
      }
      return {responseHeaders: details.responseHeaders};
    },
    {urls: ["<all_urls>"]},
    ["responseHeaders"]
  );
  
  // Calculate security score based on headers
  function calculateSecurityScore(headers) {
    let score = 0;
    let maxScore = 0;
    
    // CSP scoring
    maxScore += 30;
    if (headers['content-security-policy']) {
      score += 15;
      
      const csp = headers['content-security-policy'];
      if (!csp.includes('unsafe-inline') && !csp.includes('unsafe-eval')) {
        score += 10;
      }
      if (csp.includes('report-uri') || csp.includes('report-to')) {
        score += 5;
      }
    }
    
    // HSTS scoring
    maxScore += 20;
    if (headers['strict-transport-security']) {
      score += 10;
      const hsts = headers['strict-transport-security'];
      if (hsts.includes('max-age=') && parseInt(hsts.match(/max-age=(\d+)/)[1]) >= 15768000) {
        score += 5;
      }
      if (hsts.includes('includeSubDomains')) {
        score += 3;
      }
      if (hsts.includes('preload')) {
        score += 2;
      }
    }
    
    // X-Content-Type-Options scoring
    maxScore += 10;
    if (headers['x-content-type-options'] === 'nosniff') {
      score += 10;
    }
    
    // X-Frame-Options scoring
    maxScore += 10;
    if (headers['x-frame-options']) {
      score += 10;
    }
    
    // Referrer-Policy scoring
    maxScore += 10;
    if (headers['referrer-policy']) {
      score += 10;
    }
    
    return Math.round((score / maxScore) * 100);
  }
  
  // Update extension icon based on security score
  function updateIcon(tabId, score) {
    if (!extensionEnabled) {
      setDisabledIcon(tabId);
      return;
    }
    
    let iconPath;
    
    if (score >= 80) {
      iconPath = "../icons/icon-green-48.png";
    } else if (score >= 50) {
      iconPath = "../icons/icon-yellow-48.png";
    } else {
      iconPath = "../icons/icon-red-48.png";
    }
    
    browser.browserAction.setIcon({
      path: iconPath,
      tabId: tabId
    });
    
    browser.browserAction.setBadgeText({
      text: score.toString(),
      tabId: tabId
    });
    
    browser.browserAction.setBadgeBackgroundColor({
      color: score >= 80 ? "green" : score >= 50 ? "orange" : "red",
      tabId: tabId
    });
  }
  
  // Set icon for disabled state
  function setDisabledIcon(tabId) {
    browser.browserAction.setIcon({
      path: "../icons/icon-disabled-48.png",
      tabId: tabId
    });
    
    browser.browserAction.setBadgeText({
      text: "",
      tabId: tabId
    });
  }
  
  // Update all tab icons based on current state
  function updateAllIcons() {
    browser.tabs.query({}).then(tabs => {
      tabs.forEach(tab => {
        if (!extensionEnabled) {
          setDisabledIcon(tab.id);
        } else if (headerStore[tab.id]) {
          updateIcon(tab.id, headerStore[tab.id].score);
        } else {
          browser.browserAction.setIcon({
            path: "../icons/icon-48.png",
            tabId: tab.id
          });
          browser.browserAction.setBadgeText({
            text: "",
            tabId: tab.id
          });
        }
      });
    });
  }
  
  // Tab update handler
  browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
      if (!extensionEnabled) {
        setDisabledIcon(tabId);
      } else if (headerStore[tabId]) {
        updateIcon(tabId, headerStore[tabId].score);
      }
    }
  });
  
  // Tab activation handler
  browser.tabs.onActivated.addListener((activeInfo) => {
    if (!extensionEnabled) {
      setDisabledIcon(activeInfo.tabId);
    } else if (headerStore[activeInfo.tabId]) {
      updateIcon(activeInfo.tabId, headerStore[activeInfo.tabId].score);
    } else {
      browser.browserAction.setIcon({
        path: "../icons/icon-48.png",
        tabId: activeInfo.tabId
      });
      browser.browserAction.setBadgeText({
        text: "",
        tabId: activeInfo.tabId
      });
    }
  });
  
  // Message handler for popup communication
  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "getHeaderData") {
      browser.tabs.query({active: true, currentWindow: true}, tabs => {
        if (tabs[0]) {
          sendResponse({
            data: headerStore[tabs[0].id] || null,
            extensionEnabled: extensionEnabled
          });
        } else {
          sendResponse({
            data: null,
            extensionEnabled: extensionEnabled
          });
        }
      });
      return true;
    } else if (message.action === "setExtensionEnabled") {
      extensionEnabled = message.enabled;
      browser.storage.local.set({ extensionEnabled: extensionEnabled });
      
      updateAllIcons();
      
      sendResponse({ success: true });
      return true;
    }
  });